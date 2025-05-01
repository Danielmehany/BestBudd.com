require("dotenv").config();
const sanitizeHTML = require("sanitize-html");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const express = require("express");
const path = require("path");
//const db = require("better-sqlite3")("BestBudd.db");

const DB_FILE = process.env.DATABASE_PATH || path.join("/data", "BestBudd.db");
const Database = require("better-sqlite3");
const db = new Database(DB_FILE);

// Database setup
db.pragma("journal_mode = WAL");
const app = express();

// Middleware setup
app.use("/views", express.static(path.join(__dirname, "views")));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(cookieParser());

// Database tables creation
db.prepare(`
  CREATE TABLE IF NOT EXISTS teachers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    classcode TEXT NOT NULL UNIQUE
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    classcode TEXT NOT NULL
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS students_phone (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    contactName TEXT NOT NULL,
    phoneNumber TEXT NOT NULL,
    studentid INTEGER,
    FOREIGN KEY(studentid) REFERENCES students(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS students_website (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    websiteName TEXT NOT NULL,
    websiteURL TEXT NOT NULL,
    studentid INTEGER,
    FOREIGN KEY(studentid) REFERENCES students(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS students_schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    eventName TEXT NOT NULL,
    eventStartTime TEXT NOT NULL,
    eventEndTime TEXT NOT NULL,
    studentid INTEGER,
    FOREIGN KEY(studentid) REFERENCES students(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS students_reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    reminder TEXT NOT NULL,
    studentid INTEGER,
    FOREIGN KEY(studentid) REFERENCES students(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS teacher_reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT NOT NULL,
    reminder TEXT NOT NULL,
    teacherId INTEGER NOT NULL,
    classcode TEXT NOT NULL,
    FOREIGN KEY(teacherId) REFERENCES teachers(id)
  )
`).run();

// Authentication middleware
app.use(function(req, res, next) {
  res.locals.errors = [];
  
  try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
    req.user = decoded;
  } catch (err) {
    req.user = false;
  }

  res.locals.user = req.user;
  next();
});

// Role-based middleware
function mustBeStudent(req, res, next) {
  if (req.user && req.user.role === "student") return next();
  return res.redirect("/");
}

function mustBeTeacher(req, res, next) {
  if (req.user && req.user.role === "teacher") return next();
  return res.redirect("/");
}

// Landing page
app.get("/", (req, res) => {
  if (req.user && req.user.role === "student") return res.redirect("/student-home");
  if (req.user && req.user.role === "teacher") return res.redirect("/teacher-home");
  res.render("LandingPage");
});

//////////////////////
// Teacher Routes
//////////////////////

app.get("/teacher-signup", (req, res) => {
  res.render("TeacherSignup", { errors: [] });
});

app.get("/teacher-login", (req, res) => {
  res.render("TeacherLogin", { errors: [] });
});

app.post("/teacher-signup", (req, res) => {
  const errors = [];

  // Input validation
  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";
  if (typeof req.body.classcode !== "string") req.body.classcode = "";

  req.body.username = req.body.username.trim();
  req.body.classcode = req.body.classcode.trim();

  if (req.body.username === "") errors.push("You must provide a username.");
  if (req.body.password === "") errors.push("You must provide a password.");
  if (req.body.classcode === "") errors.push("You must provide a class code.");

  if (req.body.username && req.body.username.length < 6) 
    errors.push("Username must be at least 6 characters.");
  if (req.body.username && req.body.username.length > 20)
    errors.push("Username must be less than 20 characters.");
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain letters & numbers.");

  if (req.body.password && req.body.password.length < 8)
    errors.push("Password must be at least 8 characters.");
  if (req.body.password && req.body.password.length > 20)
    errors.push("Password must be less than 20 characters.");

  if (req.body.classcode && req.body.classcode.length < 8)
    errors.push("Class code must be at least 8 characters.");
  if (req.body.classcode && req.body.classcode.length > 20)
    errors.push("Class code must be less than 20 characters.");

  // Check for existing username
  const teacherUsernameStmt = db.prepare("SELECT * FROM teachers WHERE username = ?");
  const studentUsernameStmt = db.prepare("SELECT * FROM students WHERE username = ?");
  const teacherCheck1 = teacherUsernameStmt.get(req.body.username);
  const teacherCheck2 = studentUsernameStmt.get(req.body.username);
  if (teacherCheck1 || teacherCheck2) errors.push("That username is already taken.");

  // Check for existing classcode
  const classcodeStmt = db.prepare("SELECT * FROM teachers WHERE classcode = ?");
  const classcodeCheck = classcodeStmt.get(req.body.classcode);
  if (classcodeCheck) errors.push("That class code is already taken.");

  if (errors.length) return res.render("TeacherSignup", { errors });

  // Create new teacher
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(req.body.password, salt);

  const insertTeacherStmt = db.prepare("INSERT INTO teachers (username, password, classcode) VALUES (?, ?, ?)");
  const result = insertTeacherStmt.run(req.body.username, hashedPassword, req.body.classcode);

  const teacherLookupStmt = db.prepare("SELECT * FROM teachers WHERE ROWID = ?");
  const newTeacher = teacherLookupStmt.get(result.lastInsertRowid);

  const payload = {
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    userid: newTeacher.id,
    username: newTeacher.username,
    classcode: newTeacher.classcode,
    role: "teacher"
  };

  const ourTokenValue = jwt.sign(payload, process.env.JWTSECRET);

  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
  });

  res.redirect("/teacher-login");
});

app.post("/teacher-login", (req, res) => {
  let errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";
  req.body.username = req.body.username.trim();

  if (req.body.username === "") errors.push("Invalid username / password.");
  if (req.body.password === "") errors.push("Invalid username / password.");

  if (errors.length) return res.render("TeacherLogin", { errors });

  const teacherStmt = db.prepare("SELECT * FROM teachers WHERE username = ?");
  const teacher = teacherStmt.get(req.body.username);

  if (!teacher) {
    errors.push("Invalid username / password.");
    return res.render("TeacherLogin", { errors });
  }

  const isPasswordValid = bcrypt.compareSync(req.body.password, teacher.password);
  if (!isPasswordValid) {
    errors.push("Invalid username / password.");
    return res.render("TeacherLogin", { errors });
  }

  const tokenPayload = {
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    teacherId: teacher.id,
    username: teacher.username,
    classcode: teacher.classcode,
    role: "teacher"
  };

  const token = jwt.sign(tokenPayload, process.env.JWTSECRET);

  res.cookie("ourSimpleApp", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000
  });

  res.redirect("/teacher-home");
});

//////////////////////
// Student Routes
//////////////////////

app.get("/student-signup", (req, res) => {
  res.render("StudentSignup", { errors: [] });
});

app.post("/student-signup", (req, res) => {
  const errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";
  if (typeof req.body.classcode !== "string") req.body.classcode = "";

  req.body.username = req.body.username.trim();
  req.body.classcode = req.body.classcode.trim();

  if (req.body.username === "") errors.push("You must provide a username.");
  if (req.body.password === "") errors.push("You must provide a password.");
  if (req.body.classcode === "") errors.push("You must provide a class code.");

  if (req.body.username && req.body.username.length < 6)
    errors.push("Username must be at least 6 characters.");
  if (req.body.username && req.body.username.length > 20)
    errors.push("Username must be less than 20 characters.");
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain letters & numbers.");

  if (req.body.password && req.body.password.length < 8)
    errors.push("Password must be at least 8 characters.");
  if (req.body.password && req.body.password.length > 20)
    errors.push("Password must be less than 20 characters.");

  if (req.body.classcode && req.body.classcode.length < 8)
    errors.push("Class code must be at least 8 characters.");
  if (req.body.classcode && req.body.classcode.length > 20)
    errors.push("Class code must be less than 20 characters.");

  // Verify class code exists
  const teacherStmt = db.prepare("SELECT * FROM teachers WHERE classcode = ?");
  const teacher = teacherStmt.get(req.body.classcode);
  if (!teacher) errors.push("The provided class code does not exist.");

  // Check username availability
  const studentUsernameStmt = db.prepare("SELECT * FROM students WHERE username = ?");
  const teacherUsernameStmt = db.prepare("SELECT * FROM teachers WHERE username = ?");
  const studentCheck1 = studentUsernameStmt.get(req.body.username);
  const studentCheck2 = teacherUsernameStmt.get(req.body.username);
  if (studentCheck1 || studentCheck2) errors.push("That username is already taken.");

  if (errors.length) return res.render("StudentSignup", { errors });

  // Create student account
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(req.body.password, salt);

  const insertStudentStmt = db.prepare("INSERT INTO students (username, password, classcode) VALUES (?, ?, ?)");
  const result = insertStudentStmt.run(req.body.username, hashedPassword, req.body.classcode);

  const studentLookupStmt = db.prepare("SELECT * FROM students WHERE id = ?");
  const newStudent = studentLookupStmt.get(result.lastInsertRowid);

  const payload = {
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    studentId: newStudent.id,
    username: newStudent.username,
    classcode: newStudent.classcode,
    role: "student"
  };

  const token = jwt.sign(payload, process.env.JWTSECRET);
  res.cookie("ourSimpleApp", token, {
    httpOnly: true, 
    secure: true, 
    sameSite: "strict", 
    maxAge: 24 * 60 * 60 * 1000
  });

  res.redirect("/student-login");
});

app.get("/student-login", (req, res) => {
  res.render("StudentLogin", { errors: [] });
});

app.post("/student-login", (req, res) => {
  let errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";
  req.body.username = req.body.username.trim();

  if (req.body.username === "") errors.push("Invalid username / password.");
  if (req.body.password === "") errors.push("Invalid username / password.");
  
  if (errors.length) return res.render("StudentLogin", { errors });

  const studentStmt = db.prepare("SELECT * FROM students WHERE username = ?");
  const student = studentStmt.get(req.body.username);
  
  if (!student) {
    errors.push("Invalid username / password.");
    return res.render("StudentLogin", { errors });
  }

  const validPassword = bcrypt.compareSync(req.body.password, student.password);
  if (!validPassword) {
    errors.push("Invalid username / password.");
    return res.render("StudentLogin", { errors });
  }

  const payload = {
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    studentId: student.id,
    username: student.username,
    classcode: student.classcode,
    role: "student"
  };

  const token = jwt.sign(payload, process.env.JWTSECRET);

  res.cookie("ourSimpleApp", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000
  });

  res.redirect("/student-home");
});

//////////////////////
// Student Phone Routes
//////////////////////

app.get("/students-phone", mustBeStudent, (req, res) => {
  const stmt = db.prepare("SELECT * FROM students_phone WHERE studentid = ? ORDER BY createdDate DESC");
  const contacts = stmt.all(req.user.studentId);
  res.render("StudentPhone", { contacts, errors: [] });
});

app.post("/create-phone", mustBeStudent, (req, res) => {
  const errors = [];
  let contactName = req.body.contactName ? req.body.contactName.trim() : "";
  let phoneNumber = req.body.phoneNumber ? req.body.phoneNumber.trim() : "";

  if (!contactName || !phoneNumber) errors.push("Please fill in both fields.");
  if (contactName.length > 13) errors.push("Name must be a maximum of 13 characters.");
  const phoneRegex = /^\d{3}-\d{3}-\d{4}$/;
  if (!phoneRegex.test(phoneNumber)) errors.push("Phone number must be in the format 111-111-1111.");

  if (errors.length) {
    const stmt = db.prepare("SELECT * FROM students_phone WHERE studentid = ? ORDER BY createdDate DESC");
    const contacts = stmt.all(req.user.studentId);
    return res.render("StudentPhone", { contacts, errors });
  }

  const now = new Date().toISOString();
  const insertStmt = db.prepare("INSERT INTO students_phone (createdDate, contactName, phoneNumber, studentid) VALUES (?, ?, ?, ?)");
  insertStmt.run(now, contactName, phoneNumber, req.user.studentId);
  
  res.redirect("/students-phone");
});

app.post("/delete-phone/:id", mustBeStudent, (req, res) => {
  const phoneId = req.params.id;
  const contactStmt = db.prepare("SELECT * FROM students_phone WHERE id = ? AND studentid = ?");
  const contact = contactStmt.get(phoneId, req.user.studentId);
  if (contact) db.prepare("DELETE FROM students_phone WHERE id = ?").run(phoneId);
  res.redirect("/students-phone");
});

//////////////////////
// Student Website Routes
//////////////////////

app.get("/students-website", mustBeStudent, (req, res) => {
  const stmt = db.prepare("SELECT * FROM students_website WHERE studentid = ? ORDER BY createdDate DESC");
  const websites = stmt.all(req.user.studentId);
  res.render("StudentWebsite", { websites, errors: [] });
});

app.post("/create-website", mustBeStudent, (req, res) => {
  const errors = [];
  let websiteName = req.body.websiteName ? req.body.websiteName.trim() : "";
  let websiteURL = req.body.websiteURL ? req.body.websiteURL.trim() : "";

  if (!websiteName || !websiteURL) errors.push("Please fill in both fields.");
  if (websiteName.length > 25) errors.push("Website name must be a maximum of 25 characters.");

  if (errors.length) {
    const stmt = db.prepare("SELECT * FROM students_website WHERE studentid = ? ORDER BY createdDate DESC");
    const websites = stmt.all(req.user.studentId);
    return res.render("StudentWebsite", { websites, errors });
  }

  const now = new Date().toISOString();
  const insertStmt = db.prepare("INSERT INTO students_website (createdDate, websiteName, websiteURL, studentid) VALUES (?, ?, ?, ?)");
  insertStmt.run(now, websiteName, websiteURL, req.user.studentId);
  
  res.redirect("/students-website");
});

app.post("/delete-website/:id", mustBeStudent, (req, res) => {
  const websiteId = req.params.id;
  const websiteStmt = db.prepare("SELECT * FROM students_website WHERE id = ? AND studentid = ?");
  const website = websiteStmt.get(websiteId, req.user.studentId);
  if (website) db.prepare("DELETE FROM students_website WHERE id = ?").run(websiteId);
  res.redirect("/students-website");
});

//////////////////////
// Student Schedule Routes
//////////////////////

app.get("/students-schedule", mustBeStudent, (req, res) => {
  const stmt = db.prepare("SELECT * FROM students_schedule WHERE studentid = ? ORDER BY createdDate DESC");
  const events = stmt.all(req.user.studentId);
  res.render("StudentSchedule", { events, errors: [] });
});

app.post("/create-schedule", mustBeStudent, (req, res) => {
  const errors = [];
  let eventName = req.body.eventName ? req.body.eventName.trim() : "";
  let eventStartTime = req.body.eventStartTime ? req.body.eventStartTime.trim() : "";
  let eventEndTime = req.body.eventEndTime ? req.body.eventEndTime.trim() : "";

  if (!eventName || !eventStartTime || !eventEndTime) errors.push("Please fill in all fields.");
  if (eventName.length > 15) errors.push("Event name must be a maximum of 15 characters.");

  if (errors.length) {
    const stmt = db.prepare("SELECT * FROM students_schedule WHERE studentid = ? ORDER BY createdDate DESC");
    const events = stmt.all(req.user.studentId);
    return res.render("StudentSchedule", { events, errors });
  }

  const now = new Date().toISOString();
  const insertStmt = db.prepare(`
    INSERT INTO students_schedule (createdDate, eventName, eventStartTime, eventEndTime, studentid) 
    VALUES (?, ?, ?, ?, ?)
  `);
  insertStmt.run(now, eventName, eventStartTime, eventEndTime, req.user.studentId);

  res.redirect("/students-schedule");
});

app.post("/delete-schedule/:id", mustBeStudent, (req, res) => {
  const id = req.params.id;
  const checkStmt = db.prepare("SELECT * FROM students_schedule WHERE id = ? AND studentid = ?");
  const evt = checkStmt.get(id, req.user.studentId);
  if (evt) db.prepare("DELETE FROM students_schedule WHERE id = ?").run(id);
  res.redirect("/students-schedule");
});

//////////////////////
// Student Reminder Routes
//////////////////////

app.get("/student-home", mustBeStudent, (req, res) => {
  const sid = req.user.studentId;

  const personal = db
    .prepare("SELECT id, createdDate, reminder FROM students_reminders WHERE studentid = ?")
    .all(sid);

  const classRems = db
    .prepare("SELECT id AS reminderId, createdDate, reminder FROM teacher_reminders WHERE classcode = ?")
    .all(req.user.classcode);

  const reminders = [
    ...personal.map(r => ({ 
      id: r.id, 
      createdDate: r.createdDate, 
      reminder: r.reminder, 
      source: "personal" 
    })),
    ...classRems.map(r => ({ 
      id: r.reminderId, 
      createdDate: r.createdDate, 
      reminder: r.reminder, 
      source: "class" 
    }))
  ].sort((a,b) => new Date(b.createdDate) - new Date(a.createdDate));

  res.render("StudentHome", { reminders, errors: [] });
});

app.post("/create-reminder", mustBeStudent, (req, res) => {
  const errors = [];
  const text = (req.body.reminder || "").trim();

  if (!text) errors.push("Please enter a reminder.");
  if (text.length > 250) errors.push("Reminder must be 250 characters or fewer.");

  if (errors.length) {
    const sid = req.user.studentId;
    const personal = db
      .prepare("SELECT id, createdDate, reminder FROM students_reminders WHERE studentid = ?")
      .all(sid);

    const classRems = db
      .prepare("SELECT id AS reminderId, createdDate, reminder FROM teacher_reminders WHERE classcode = ?")
      .all(req.user.classcode);

    const reminders = [
      ...personal.map(r => ({
        id: r.id,
        createdDate: r.createdDate,
        reminder: r.reminder,
        source: "personal"
      })),
      ...classRems.map(r => ({
        id: r.reminderId,
        createdDate: r.createdDate,
        reminder: r.reminder,
        source: "class"
      }))
    ].sort((a, b) => new Date(b.createdDate) - new Date(a.createdDate));

    return res.render("StudentHome", { reminders, errors });
  }

  const now = new Date().toISOString();
  db.prepare(
    "INSERT INTO students_reminders (createdDate, reminder, studentid) VALUES (?, ?, ?)"
  ).run(now, text, req.user.studentId);

  res.redirect("/student-home");
});

// Enable foreign keys
db.pragma("foreign_keys = ON");

app.post("/delete-reminder/:id", mustBeStudent, (req, res) => {
  const reminderId = req.params.id;
  const studentId = req.user.studentId;
  const referer = req.headers.referer || "";

  const own = db.prepare(
    "SELECT 1 FROM students_reminders WHERE id = ? AND studentid = ?"
  ).get(reminderId, studentId);

  if (own) {
    db.pragma("foreign_keys = OFF");
    db.prepare("DELETE FROM student_ratings WHERE reminderid = ? AND studentid = ?").run(reminderId, studentId);
    db.prepare("DELETE FROM students_reminders WHERE id = ? AND studentid = ?").run(reminderId, studentId);
    db.pragma("foreign_keys = ON");
  }

  if (referer.includes("/student-report")) {
    return res.redirect("/student-report");
  }
  res.redirect("/student-home");
});

app.post("/logout", (req, res) => {
  res.clearCookie("ourSimpleApp", {
    httpOnly: true,
    secure: true,
    sameSite: "strict"
  });
  res.redirect("/");
});

/////////////////////////////////
// Student Report Routes
/////////////////////////////////

db.prepare(`
  CREATE TABLE IF NOT EXISTS student_daily_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    studentid INTEGER NOT NULL,
    date TEXT NOT NULL,
    strength TEXT NOT NULL DEFAULT '',
    weakness TEXT NOT NULL DEFAULT '',
    UNIQUE(studentid, date),
    FOREIGN KEY(studentid) REFERENCES students(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS student_ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    studentid INTEGER NOT NULL,
    reminderid INTEGER NOT NULL,
    rating INTEGER NOT NULL DEFAULT 0,
    date TEXT NOT NULL,
    UNIQUE(studentid, reminderid, date),
    FOREIGN KEY(studentid) REFERENCES students(id),
    FOREIGN KEY(reminderid) REFERENCES students_reminders(id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS teacher_ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    studentid INTEGER NOT NULL,
    teacher_reminderid INTEGER NOT NULL,
    rating INTEGER NOT NULL DEFAULT 0,
    date TEXT NOT NULL,
    UNIQUE(studentid, teacher_reminderid, date),
    FOREIGN KEY(studentid) REFERENCES students(id),
    FOREIGN KEY(teacher_reminderid) REFERENCES teacher_reminders(id)
  )
`).run();

app.get("/student-report", mustBeStudent, (req, res) => {
  const sid = req.user.studentId;
  const today = new Date().toISOString().slice(0,10);

  // Purge old ratings
  db.prepare("DELETE FROM student_ratings WHERE studentid=? AND date<?").run(sid, today);
  db.prepare("DELETE FROM teacher_ratings WHERE studentid=? AND date<?").run(sid, today);

  // Upsert personal ratings
  const pers = db.prepare("SELECT id FROM students_reminders WHERE studentid=?").all(sid);
  const upSR = db.prepare(
    "INSERT OR IGNORE INTO student_ratings(studentid,reminderid,rating,date) VALUES(?,?,0,?)"
  );
  pers.forEach(r => upSR.run(sid, r.id, today));

  // Upsert class ratings
  const cls = db.prepare("SELECT id FROM teacher_reminders WHERE classcode=?").all(req.user.classcode);
  const upTR = db.prepare(
    "INSERT OR IGNORE INTO teacher_ratings(studentid,teacher_reminderid,rating,date) VALUES(?,?,0,?)"
  );
  cls.forEach(r => upTR.run(sid, r.id, today));

  // Upsert daily notes
  db.prepare(
    "INSERT OR IGNORE INTO student_daily_notes(studentid,date,strength,weakness) VALUES(?,?,'','')"
  ).run(sid, today);

  let notes = db.prepare(
    "SELECT id AS notesId, strength, weakness FROM student_daily_notes WHERE studentid=? AND date=?"
  ).get(sid, today);

  if (!notes) notes = { notesId: null, strength: "", weakness: "" };

  const report = db.prepare(`
    SELECT sr.id AS ratingId,
           r.reminder AS text,
           sr.rating AS rating,
           r.createdDate,
           'personal' AS source
      FROM student_ratings sr
      JOIN students_reminders r ON sr.reminderid=r.id
     WHERE sr.studentid=? AND sr.date=?
    UNION ALL
    SELECT tr.id AS ratingId,
           t.reminder AS text,
           tr.rating AS rating,
           t.createdDate,
           'class' AS source
      FROM teacher_ratings tr
      JOIN teacher_reminders t ON tr.teacher_reminderid=t.id
     WHERE tr.studentid=? AND tr.date=?
    ORDER BY createdDate DESC
  `).all(sid, today, sid, today);

  res.render("StudentReport", { report, notes });
});

app.post("/student-report", mustBeStudent, (req, res) => {
  let raw = req.body['reportIds[]'] || req.body.reportIds || [];
  if (!Array.isArray(raw)) raw = [raw];

  raw.forEach(rid => {
    const rating = parseInt(req.body[`rating_${rid}`], 10) || 0;
    const src = req.body[`ratingType_${rid}`];
    if (src === "class") {
      db.prepare("UPDATE teacher_ratings SET rating = ? WHERE id = ?").run(rating, rid);
    } else {
      db.prepare("UPDATE student_ratings SET rating = ? WHERE id = ?").run(rating, rid);
    }
  });

  const notesId = Number(req.body.notesId);
  const strength = (req.body.strength || "").trim();
  const weakness = (req.body.weakness || "").trim();
  db.prepare(
    "UPDATE student_daily_notes SET strength = ?, weakness = ? WHERE id = ?"
  ).run(strength, weakness, notesId);

  res.redirect("/student-report");
});

/////////////////////////////////
// Teacher Home Routes
/////////////////////////////////

app.get("/teacher-home", mustBeTeacher, (req, res) => {
  const user = { username: req.user.username, classcode: req.user.classcode };
  const students = db
    .prepare("SELECT id, username FROM students WHERE classcode = ?")
    .all(req.user.classcode);

  const classReminders = db.prepare(`
    SELECT id, reminder, createdDate
      FROM teacher_reminders
     WHERE teacherId = ? AND classcode = ?
     ORDER BY createdDate DESC
  `).all(req.user.teacherId, req.user.classcode);

  res.render("TeacherHome", { user, students, classReminders, errors: [] });
});

app.post("/create-class-reminder", mustBeTeacher, (req, res) => {
  const text = (req.body.reminder||"").trim();
  if (!text) return res.redirect("/teacher-home");

  db.prepare(`
    INSERT INTO teacher_reminders (createdDate, reminder, teacherId, classcode)
    VALUES (?, ?, ?, ?)
  `).run(new Date().toISOString(), text, req.user.teacherId, req.user.classcode);

  res.redirect("/teacher-home");
});

app.post("/delete-class-reminder/:reminderId", mustBeTeacher, (req, res) => {
  const rid = Number(req.params.reminderId);
  const ok = db.prepare("SELECT 1 FROM teacher_reminders WHERE id = ? AND teacherId = ?")
             .get(rid, req.user.teacherId);

  if (ok) {
    db.prepare("DELETE FROM teacher_ratings WHERE teacher_reminderid = ?").run(rid);
    db.prepare("DELETE FROM teacher_reminders WHERE id = ?").run(rid);
  }

  res.redirect("/teacher-home");
});

app.post("/remove-student/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db
    .prepare("SELECT classcode FROM students WHERE id = ?")
    .get(sid);

  if (!student || student.classcode !== req.user.classcode) {
    return res.redirect("/teacher-home");
  }

  db.pragma("foreign_keys = OFF");
  db.prepare("DELETE FROM student_ratings WHERE studentid = ?").run(sid);
  db.prepare("DELETE FROM teacher_ratings WHERE studentid = ?").run(sid);
  db.prepare("DELETE FROM student_daily_notes WHERE studentid = ?").run(sid);
  db.prepare("DELETE FROM students_reminders WHERE studentid = ?").run(sid);
  db.prepare("DELETE FROM students_phone WHERE studentid = ?").run(sid);
  db.prepare("DELETE FROM students_website WHERE studentid = ?").run(sid);
  db.prepare("DELETE FROM students_schedule WHERE studentid = ?").run(sid);
  db.prepare("DELETE FROM students WHERE id = ?").run(sid);
  db.pragma("foreign_keys = ON");

  res.redirect("/teacher-home");
});

//////////////////////
// Teacher View Student Routes
/////////////////////

app.get("/student-teacher-view/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db
    .prepare("SELECT id, username, classcode FROM students WHERE id = ?")
    .get(sid);
  if (!student || student.classcode !== req.user.classcode) {
    return res.redirect("/teacher-home");
  }

  const reminders = db
    .prepare("SELECT id, reminder FROM students_reminders WHERE studentid = ? ORDER BY createdDate DESC")
    .all(sid);

  res.render("StudentTeacherView", {
    user: req.user,
    student,
    reminders,
    errors: []
  });
});

app.post("/teacher-create-reminder/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db.prepare("SELECT classcode FROM students WHERE id = ?").get(sid);
  if (student && student.classcode === req.user.classcode) {
    const text = (req.body.reminder || "").trim();
    if (text) {
      db.prepare(`
        INSERT INTO students_reminders (createdDate, reminder, studentid)
        VALUES (?, ?, ?)
      `).run(new Date().toISOString(), text, sid);
    }
  }
  res.redirect(`/student-teacher-view/${sid}`);
});

app.post("/teacher-delete-reminder/:reminderId/:studentId", mustBeTeacher, (req, res) => {
  const rid = Number(req.params.reminderId);
  const sid = Number(req.params.studentId);
  const student = db.prepare("SELECT classcode FROM students WHERE id = ?").get(sid);
  const rem = db.prepare("SELECT studentid FROM students_reminders WHERE id = ?").get(rid);
  
  if (student && student.classcode === req.user.classcode && rem && rem.studentid === sid) {
    // Start transaction
    const transaction = db.transaction(() => {
      db.prepare("DELETE FROM student_ratings WHERE reminderid = ? AND studentid = ?").run(rid, sid);
      db.prepare("DELETE FROM students_reminders WHERE id = ?").run(rid);
    });
    
    // Execute transaction
    transaction();
  }
  res.redirect(`/student-teacher-view/${sid}`);
});

//////////////////////
// Teacher Phone View Routes
//////////////////////

app.get("/student-phoneT/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db
    .prepare("SELECT id, username, classcode FROM students WHERE id = ?")
    .get(sid);
  if (!student || student.classcode !== req.user.classcode) {
    return res.redirect("/teacher-home");
  }
  const contacts = db
    .prepare("SELECT * FROM students_phone WHERE studentid = ? ORDER BY createdDate DESC")
    .all(sid);
  res.render("StudentPhoneT", { user: student, contacts, errors: [] });
});

app.post("/create-phoneT/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db.prepare("SELECT id, classcode FROM students WHERE id = ?").get(sid);
  if (!student || student.classcode !== req.user.classcode) {
    return res.redirect("/teacher-home");
  }

  const name = (req.body.contactName || "").trim();
  const number = (req.body.phoneNumber || "").trim();
  const errors = [];
  if (!name || !number) errors.push("Please fill in both fields.");
  if (name.length > 13) errors.push("Name must be a maximum of 13 characters.");
  if (!/^\d{3}-\d{3}-\d{4}$/.test(number))
    errors.push("Phone number must be in the format 111-111-1111.");

  if (errors.length) {
    const contacts = db
      .prepare("SELECT * FROM students_phone WHERE studentid = ? ORDER BY createdDate DESC")
      .all(sid);
    return res.render("StudentPhoneT", { user: student, contacts, errors });
  }

  db.prepare(
    "INSERT INTO students_phone (createdDate, contactName, phoneNumber, studentid) VALUES (?, ?, ?, ?)"
  ).run(new Date().toISOString(), name, number, sid);

  res.redirect(`/student-phoneT/${sid}`);
});

app.post("/delete-phoneT/:studentId/:contactId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const cid = Number(req.params.contactId);
  const student = db.prepare("SELECT id, classcode FROM students WHERE id = ?").get(sid);
  if (student && student.classcode === req.user.classcode) {
    db.prepare("DELETE FROM students_phone WHERE id = ? AND studentid = ?").run(cid, sid);
  }
  res.redirect(`/student-phoneT/${sid}`);
});

//////////////////////
// Teacher Website View Routes
//////////////////////

app.get("/student-websiteT/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db.prepare("SELECT id, username, classcode FROM students WHERE id = ?").get(sid);
  if (!student || student.classcode !== req.user.classcode) {
    return res.redirect("/teacher-home");
  }
  const websites = db
    .prepare("SELECT * FROM students_website WHERE studentid = ? ORDER BY createdDate DESC")
    .all(sid);
  res.render("StudentWebsiteT", { user: student, websites, errors: [] });
});

app.post("/create-websiteT/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db.prepare("SELECT id, classcode FROM students WHERE id = ?").get(sid);
  if (!student || student.classcode !== req.user.classcode) {
    return res.redirect("/teacher-home");
  }

  const name = (req.body.websiteName || "").trim();
  const url = (req.body.websiteURL || "").trim();
  const errors = [];
  if (!name || !url) errors.push("Please fill in both fields.");
  if (name.length > 25) errors.push("Website name must be a maximum of 25 characters.");

  if (errors.length) {
    const sites = db
      .prepare("SELECT * FROM students_website WHERE studentid = ? ORDER BY createdDate DESC")
      .all(sid);
    return res.render("StudentWebsiteT", { user: student, websites: sites, errors });
  }

  db.prepare(
    "INSERT INTO students_website (createdDate, websiteName, websiteURL, studentid) VALUES (?, ?, ?, ?)"
  ).run(new Date().toISOString(), name, url, sid);

  res.redirect(`/student-websiteT/${sid}`);
});

app.post("/delete-websiteT/:studentId/:siteId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const id = Number(req.params.siteId);
  const student = db.prepare("SELECT id, classcode FROM students WHERE id = ?").get(sid);
  if (student && student.classcode === req.user.classcode) {
    db.prepare("DELETE FROM students_website WHERE id = ? AND studentid = ?").run(id, sid);
  }
  res.redirect(`/student-websiteT/${sid}`);
});

//////////////////////
// Teacher Schedule View Routes
//////////////////////

app.get("/student-scheduleT/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db.prepare("SELECT id, username, classcode FROM students WHERE id = ?").get(sid);
  if (!student || student.classcode !== req.user.classcode) {
    return res.redirect("/teacher-home");
  }
  const events = db
    .prepare("SELECT * FROM students_schedule WHERE studentid = ? ORDER BY createdDate DESC")
    .all(sid);
  res.render("StudentScheduleT", { user: student, events, errors: [] });
});

app.post("/create-scheduleT/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db.prepare("SELECT id, classcode FROM students WHERE id = ?").get(sid);
  if (!student || student.classcode !== req.user.classcode) {
    return res.redirect("/teacher-home");
  }

  const name = (req.body.eventName || "").trim();
  const start = (req.body.eventStartTime || "").trim();
  const end = (req.body.eventEndTime || "").trim();
  const errors = [];
  if (!name || !start || !end) errors.push("Please fill in all fields.");
  if (name.length > 15) errors.push("Event name must be a maximum of 15 characters.");
  if (start >= end) errors.push("Start time must be before end time.");

  if (errors.length) {
    const evs = db.prepare("SELECT * FROM students_schedule WHERE studentid = ? ORDER BY createdDate DESC").all(sid);
    return res.render("StudentScheduleT", { user: student, events: evs, errors });
  }

  db.prepare(
    "INSERT INTO students_schedule (createdDate, eventName, eventStartTime, eventEndTime, studentid) VALUES (?, ?, ?, ?, ?)"
  ).run(new Date().toISOString(), name, start, end, sid);

  res.redirect(`/student-scheduleT/${sid}`);
});

app.post("/delete-scheduleT/:studentId/:eventId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const id = Number(req.params.eventId);
  const student = db.prepare("SELECT id, classcode FROM students WHERE id = ?").get(sid);
  if (student && student.classcode === req.user.classcode) {
    db.prepare("DELETE FROM students_schedule WHERE id = ? AND studentid = ?").run(id, sid);
  }
  res.redirect(`/student-scheduleT/${sid}`);
});

//////////////////////
// Teacher Report View Routes
//////////////////////

app.get("/student-reportT/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const student = db.prepare("SELECT id, username, classcode FROM students WHERE id = ?")
                    .get(sid);
  if (!student || student.classcode !== req.user.classcode) {
    return res.redirect("/teacher-home");
  }

  const today = new Date().toISOString().slice(0,10);

  // Ensure we have ratings rows for both personal & class reminders
  db.prepare(`
    INSERT OR IGNORE INTO student_ratings (studentid, reminderid, rating, date)
    SELECT ?, id, 0, ? FROM students_reminders WHERE studentid = ?
  `).run(sid, today, sid);

  db.prepare(`
    INSERT OR IGNORE INTO teacher_ratings (studentid, teacher_reminderid, rating, date)
    SELECT ?, id, 0, ? FROM teacher_reminders WHERE classcode = ?
  `).run(sid, today, student.classcode);

  // Ensure a daily notes row exists
  db.prepare(`
    INSERT OR IGNORE INTO student_daily_notes (studentid, date, strength, weakness)
    VALUES (?, ?, '', '')
  `).run(sid, today);

  // Fetch notes (may come back undefined)
  let notes = db.prepare(`
    SELECT id AS notesId, strength, weakness
      FROM student_daily_notes
     WHERE studentid = ? AND date = ?
  `).get(sid, today);

  // FALLBACK so EJS always sees an object
  if (!notes) {
    notes = { notesId: null, strength: "", weakness: "" };
  }

  // Combined personal + class ratings
  const report = db.prepare(`
    SELECT sr.id AS ratingId,
           r.reminder AS text,
           sr.rating AS rating,
           'personal' AS source,
           r.createdDate
      FROM student_ratings sr
      JOIN students_reminders r ON r.id = sr.reminderid
     WHERE sr.studentid = ? AND sr.date = ?
    UNION ALL
    SELECT tr.id AS ratingId,
           t.reminder AS text,
           tr.rating AS rating,
           'class' AS source,
           t.createdDate
      FROM teacher_ratings tr
      JOIN teacher_reminders t ON t.id = tr.teacher_reminderid
     WHERE tr.studentid = ? AND tr.date = ?
    ORDER BY createdDate DESC
  `).all(sid, today, sid, today);

  res.render("StudentReportT", {
    user: student,
    report,
    notes
  });
});

app.post("/student-reportT/:studentId", mustBeTeacher, (req, res) => {
  const sid = Number(req.params.studentId);
  const rawIds = req.body.reportIds || req.body['reportIds[]'] || [];
  const reportIds = Array.isArray(rawIds) ? rawIds : [rawIds];

  const updateRating = db.prepare(`
    UPDATE student_ratings
       SET rating = ?
     WHERE id = ?
  `);
  reportIds.forEach(rid => {
    const val = parseInt(req.body[`rating_${rid}`], 10) || 0;
    updateRating.run(val, rid);
  });

  db.prepare(`
    UPDATE student_daily_notes
       SET strength = ?, weakness = ?
     WHERE id = ?
  `).run(req.body.strength||"", req.body.weakness||"", req.body.notesId);

  res.redirect(`/student-reportT/${sid}`);
});

//////////////////////
// Server Startup
//////////////////////

app.listen(3000, '0.0.0.0', () => {
  console.log("Server is listening on port 3000");
});