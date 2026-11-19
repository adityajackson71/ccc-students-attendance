const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");

const SECRET =
  process.env.SESSION_SECRET || "change-this-secret-before-production";

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ================================
// DATABASE
// ================================

function loadDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  if (!fs.existsSync(DB_FILE)) {
    const initialDb = {
      appName: "CCC Students Attendance",
      admin: null,
      teachers: [],
      students: [],
      attendance: []
    };

    fs.writeFileSync(DB_FILE, JSON.stringify(initialDb, null, 2));
  }

  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function saveDb(db) {
  fs.mkdirSync(DATA_DIR, { recursive: true });

  const tempFile = DB_FILE + ".tmp";

  fs.writeFileSync(tempFile, JSON.stringify(db, null, 2));
  fs.renameSync(tempFile, DB_FILE);
}

// ================================
// HELPERS
// ================================

const generateId = () => crypto.randomUUID();

function today() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");

  return `${year}-${month}-${day}`;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");

  return { salt, hash };
}

function verifyPassword(password, saved) {
  if (!saved || !saved.salt || !saved.hash) return false;

  const attempt = crypto.scryptSync(password, saved.salt, 64);
  const original = Buffer.from(saved.hash, "hex");

  return (
    attempt.length === original.length &&
    crypto.timingSafeEqual(attempt, original)
  );
}

function createToken(user) {
  const payload = Buffer.from(
    JSON.stringify({
      id: user.id,
      role: user.role,
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000
    })
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", SECRET)
    .update(payload)
    .digest("hex");

  return `${payload}.${signature}`;
}

// ================================
// AUTHENTICATION
// ================================

function authenticate(req, res, next) {
  const authorization = req.headers.authorization || "";
  const token = authorization.replace(/^Bearer\s+/i, "");

  if (!token) {
    return res.status(401).json({
      error: "Please sign in."
    });
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return res.status(401).json({
      error: "Invalid session."
    });
  }

  const [payload, signature] = parts;

  const expectedSignature = crypto
    .createHmac("sha256", SECRET)
    .update(payload)
    .digest("hex");

  const suppliedBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (
    suppliedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)
  ) {
    return res.status(401).json({
      error: "Invalid session."
    });
  }

  try {
    const user = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!user.exp || user.exp < Date.now()) {
      return res.status(401).json({
        error: "Session expired. Please sign in again."
      });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid session."
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

// ================================
// HEALTH CHECK
// ================================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    app: "CCC Students Attendance",
    message: "Backend is running successfully."
  });
});

// ================================
// FIRST-TIME SETUP
// ================================

app.get("/api/setup-status", (req, res) => {
  try {
    const db = loadDb();

    res.json({
      setupRequired: !db.admin
    });
  } catch (error) {
    console.error("Setup status error:", error);

    res.status(500).json({
      error: "Unable to check setup status."
    });
  }
});

app.post("/api/setup", (req, res) => {
  try {
    const db = loadDb();

    if (db.admin) {
      return res.status(409).json({
        error: "Administrator setup has already been completed."
      });
    }

    const { appName, name, email, password } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Please fill in all required fields."
      });
    }

    if (String(password).length < 8) {
      return res.status(400).json({
        error: "Password must contain at least 8 characters."
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const credentials = hashPassword(String(password));

    db.appName = String(
      appName || "CCC Students Attendance"
    ).slice(0, 60);

    db.admin = {
      id: generateId(),
      name: String(name).trim().slice(0, 80),
      email: normalizedEmail,
      ...credentials
    };

    saveDb(db);

    const user = {
      id: db.admin.id,
      role: "admin"
    };

    res.json({
      token: createToken(user),
      user: {
        id: user.id,
        role: user.role,
        name: db.admin.name
      },
      appName: db.appName
    });
  } catch (error) {
    console.error("Setup error:", error);

    res.status(500).json({
      error: "Unable to complete administrator setup."
    });
  }
});

// ================================
// LOGIN
// ================================

app.post("/api/login", (req, res) => {
  try {
    const db = loadDb();

    const { email, password } = req.body || {};

    const normalizedEmail = String(email || "")
      .trim()
      .toLowerCase();

    let account = null;
    let role = null;

    if (
      db.admin &&
      db.admin.email === normalizedEmail
    ) {
      account = db.admin;
      role = "admin";
    }

    if (!account) {
      account = db.teachers.find(
        teacher => teacher.email === normalizedEmail
      );

      if (account) {
        role = "teacher";
      }
    }

    if (
      !account ||
      !verifyPassword(String(password || ""), account)
    ) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const user = {
      id: account.id,
      role
    };

    res.json({
      token: createToken(user),
      user: {
        id: account.id,
        role,
        name: account.name
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Unable to sign in."
    });
  }
});

// ================================
// CURRENT USER
// ================================

app.get("/api/me", authenticate, (req, res) => {
  try {
    const db = loadDb();

    const account =
      req.user.role === "admin"
        ? db.admin
        : db.teachers.find(
            teacher => teacher.id === req.user.id
          );

    if (!account) {
      return res.status(401).json({
        error: "Account not found."
      });
    }

    res.json({
      user: {
        id: account.id,
        role: req.user.role,
        name: account.name
      },
      appName: db.appName || "CCC Students Attendance"
    });
  } catch (error) {
    console.error("User error:", error);

    res.status(500).json({
      error: "Unable to load user information."
    });
  }
});

// ================================
// DASHBOARD
// ================================

app.get("/api/dashboard", authenticate, (req, res) => {
  try {
    const db = loadDb();

    res.json({
      teachers: db.teachers.map(teacher => ({
        id: teacher.id,
        name: teacher.name,
        email: teacher.email
      })),

      students: db.students,

      attendance: db.attendance,

      date: today()
    });
  } catch (error) {
    console.error("Dashboard error:", error);

    res.status(500).json({
      error: "Unable to load dashboard."
    });
  }
});

// ================================
// ADD TEACHER
// ================================

app.post(
  "/api/teachers",
  authenticate,
  adminOnly,
  (req, res) => {
    try {
      const db = loadDb();

      const { name, email, password } = req.body || {};

      if (!name || !email || !password) {
        return res.status(400).json({
          error: "Please enter teacher name, email and password."
        });
      }

      if (String(password).length < 8) {
        return res.status(400).json({
          error: "Teacher password must contain at least 8 characters."
        });
      }

      const normalizedEmail = String(email)
        .trim()
        .toLowerCase();

      if (
        db.admin?.email === normalizedEmail ||
        db.teachers.some(
          teacher => teacher.email === normalizedEmail
        )
      ) {
        return res.status(409).json({
          error: "This email is already registered."
        });
      }

      const credentials = hashPassword(String(password));

      db.teachers.push({
        id: generateId(),
        name: String(name).trim().slice(0, 80),
        email: normalizedEmail,
        ...credentials
      });

      saveDb(db);

      res.json({
        ok: true,
        message: "Teacher added successfully."
      });
    } catch (error) {
      console.error("Add teacher error:", error);

      res.status(500).json({
        error: "Unable to add teacher."
      });
    }
  }
);

// ================================
// DELETE TEACHER
// ================================

app.delete(
  "/api/teachers/:id",
  authenticate,
  adminOnly,
  (req, res) => {
    try {
      const db = loadDb();

      db.teachers = db.teachers.filter(
        teacher => teacher.id !== req.params.id
      );

      db.attendance = db.attendance.filter(
        record =>
          !(
            record.personType === "teacher" &&
            record.personId === req.params.id
          )
      );

      saveDb(db);

      res.json({
        ok: true,
        message: "Teacher deleted successfully."
      });
    } catch (error) {
      console.error("Delete teacher error:", error);

      res.status(500).json({
        error: "Unable to delete teacher."
      });
    }
  }
);

// ================================
// ADD STUDENT
// ================================

app.post(
  "/api/students",
  authenticate,
  adminOnly,
  (req, res) => {
    try {
      const db = loadDb();

      const { name, batch = "" } = req.body || {};

      if (!name) {
        return res.status(400).json({
          error: "Please enter student name."
        });
      }

      db.students.push({
        id: generateId(),
        name: String(name).trim().slice(0, 80),
        batch: String(batch).trim().slice(0, 60)
      });

      saveDb(db);

      res.json({
        ok: true,
        message: "Student added successfully."
      });
    } catch (error) {
      console.error("Add student error:", error);

      res.status(500).json({
        error: "Unable to add student."
      });
    }
  }
);

// ================================
// DELETE STUDENT
// ================================

app.delete(
  "/api/students/:id",
  authenticate,
  adminOnly,
  (req, res) => {
    try {
      const db = loadDb();

      db.students = db.students.filter(
        student => student.id !== req.params.id
      );

      db.attendance = db.attendance.filter(
        record =>
          !(
            record.personType === "student" &&
            record.personId === req.params.id
          )
      );

      saveDb(db);

      res.json({
        ok: true,
        message: "Student deleted successfully."
      });
    } catch (error) {
      console.error("Delete student error:", error);

      res.status(500).json({
        error: "Unable to delete student."
      });
    }
  }
);

// ================================
// MARK ATTENDANCE
// ================================

app.post("/api/attendance", authenticate, (req, res) => {
  try {
    const db = loadDb();

    const {
      personId,
      personType,
      status,
      date = today()
    } = req.body || {};

    if (!personId || !personType || !status) {
      return res.status(400).json({
        error: "Attendance details are incomplete."
      });
    }

    if (!["teacher", "student"].includes(personType)) {
      return res.status(400).json({
        error: "Invalid person type."
      });
    }

    if (!["Present", "Absent", "Leave"].includes(status)) {
      return res.status(400).json({
        error: "Invalid attendance status."
      });
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({
        error: "Invalid attendance date."
      });
    }

    // Teachers can only mark their own attendance.
    if (
      req.user.role === "teacher" &&
      (
        personType !== "teacher" ||
        personId !== req.user.id
      )
    ) {
      return res.status(403).json({
        error: "Teachers can only mark their own attendance."
      });
    }

    if (
      personType === "teacher" &&
      !db.teachers.some(
        teacher => teacher.id === personId
      )
    ) {
      return res.status(404).json({
        error: "Teacher not found."
      });
    }

    if (
      personType === "student" &&
      (
        req.user.role !== "admin" ||
        !db.students.some(
          student => student.id === personId
        )
      )
    ) {
      return res.status(403).json({
        error: "You cannot mark this attendance."
      });
    }

    const existing = db.attendance.find(
      record =>
        record.personId === personId &&
        record.personType === personType &&
        record.date === date
    );

    if (existing) {
      existing.status = status;
      existing.markedBy = req.user.id;
    } else {
      db.attendance.push({
        id: generateId(),
        personId,
        personType,
        status,
        date,
        markedBy: req.user.id
      });
    }

    saveDb(db);

    res.json({
      ok: true,
      message: "Attendance saved successfully."
    });
  } catch (error) {
    console.error("Attendance error:", error);

    res.status(500).json({
      error: "Unable to save attendance."
    });
  }
});

// ================================
// UNKNOWN API ROUTES
// ================================

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found."
  });
});

// ================================
// FRONTEND ROUTE
// ================================

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

// ================================
// START SERVER
// ================================

app.listen(PORT, () => {
  console.log(
    `CCC Students Attendance running on port ${PORT}`
  );
});
