PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('student','recruiter','admin')),
  is_approved INTEGER NOT NULL DEFAULT 0, -- 0=pending, 1=approved
  resume_path TEXT,                    -- only for students
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);



CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  company TEXT NOT NULL,
  location TEXT,
  job_type TEXT,
  description TEXT,
  requirements TEXT,
  salary_min INTEGER, 
  salary_max INTEGER, 
  posted_by INTEGER NOT NULL,
  deadline DATE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (posted_by) REFERENCES users(id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS applications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  cover_note TEXT,
  status TEXT NOT NULL DEFAULT 'applied', -- 'applied','reviewed','accepted','rejected'
  applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (job_id, student_id),
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);