import express from 'express';
import { engine } from 'express-handlebars';
import sqlite3 from 'sqlite3'
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import path from 'path'

const jwtSecret = "authsecret";

const upload = multer({
    dest: './uploads/', // upload directory
    limits: {
        fileSize: 8000000 // 8MB limit
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(null, false);
        }
    }
});
//DATABASE STRUCTURE
const db = new sqlite3.Database('./db/database.db');
db.run(`
    CREATE TABLE IF NOT EXISTS user (
      id INTEGER PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      fullname TEXT NOT NULL,
      password  TEXT NOT NULL,
      role TEXT NOT NULL
    );
  `);
db.run(`
     CREATE TABLE IF NOT EXISTS job (
      id INTEGER PRIMARY KEY,
      position TEXT NOT NULL,
      description  TEXT NOT NULL,
      salary TEXT NOT NULL,
      isApproved TEXT NOT NULL
    );
`)
db.run(`
    CREATE TABLE IF NOT EXISTS application (
     id INTEGER PRIMARY KEY,
     fullname TEXT NOT NULL,
     email  TEXT NOT NULL,
     position TEXT NOT NULL,
     status TEXT NOT NULL,
     cvId TEXT NOT NULL
   );
`)

//db.run(`DROP TABLE user`)
//db.run(`ALTER TABLE application DELETE status TEXT;`)
//createAdmin()


const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"))
app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.set('views', './views');
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser());


function userMiddleware(req, res, next) {
    const token = req.cookies.token; //REQUEST COOKIES
    if (!token) {
        res.redirect("/login");
        return;
    }
    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err || decoded.role !== 'user') {
            res.redirect('/login'); //SEND USER TO LOGIN IF NOT DONE
            return;
        }

        req.user = decoded;
        next();
    });
}
function adminMiddleware(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        res.redirect("/login");//SEND ADMIN TO LOGIN IF NOT DONE
        return;
    }
    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err || decoded.role !== 'admin') { //VERIFY THE TOKEN
            res.redirect('/login');
            return;
        }
        req.user = decoded;
        next();
    });
}

app.get("/", (req, res) => {
    const token = req.cookies.token;
    res.render("home", { token })   //KEEPS GOING IF SIGNED IN
})

//JOBS LOGIC
app.get("/admin", adminMiddleware, (req, res) => {
    db.all(`SELECT * FROM job`, (err, rows) => {
        res.render("admin", { jobs: rows })
    })
})
app.get("/admin/new-job", adminMiddleware, (req, res) => {
    const user = req.user
    if (user.role !== 'admin') {
        return res.redirect('/login')
    }
    res.render("new-job")
})
app.post("/admin/new-job", adminMiddleware, (req, res) => {
    const body = req.body
    db.run(`INSERT INTO job (position, description, salary, isApproved) VALUES (?, ?, ?, ?)`, [body.position, body.description, body.salary, 'pending'], (err => {
        if (err) {
            res.render('new-job', { error: 'Error creating job' });
        } else {
            res.redirect('/admin');
        }
    }))
})
app.post("/admin/delete-job", adminMiddleware, (req, res) => {
    const id = req.body.id
    db.run(`DELETE FROM job WHERE id = ?`, [id], (err) => {
        res.redirect('/admin');
    })
})

//APPLY LOGIC
app.get("/jobs", (req, res) => {
    const token = req.cookies.token
    db.all(`SELECT * FROM job WHERE isApproved = 'approved'`, (err, rows) => {
        res.render("jobs", { jobs: rows, token })
    })
})
app.get("/jobs/apply/:jobId", userMiddleware, (req, res) => {
    const jobId = req.params.jobId;
    const user = req.user;
    db.all("SELECT * FROM job WHERE id = ?", [jobId], (err, rows) => {
        if (rows && rows.length > 0) {
            const job = rows[0]
            res.render("apply", { job, user })
        }
    })
})
app.post("/jobs/apply", userMiddleware, upload.single('file'), (req, res) => {
    const body = req.body

    db.run(`INSERT INTO application (fullname, email, position, status, cvId) VALUES (?, ?, ?, ?, ?)`,
        [body.fullname, body.email, body.position, "pending", req.file.filename],
        (err => {
            if (err) {
                res.render('apply', { error: err.message });
            } else {
                res.redirect('/my-jobs?applied=true');
            }
        }))
})
app.get("/admin/applications", adminMiddleware, (req, res) => {
    db.all(`SELECT * FROM application`, (err, rows) => {
        res.render("applications", { applications: rows, isAdmin: true })
    })
})
app.get("/my-jobs", userMiddleware, (req, res) => {
    const user = req.user;
    db.all(`SELECT * FROM application WHERE email = ? `, [user.email], (err, rows) => {
        res.render("applications", { applications: rows, isAdmin: user.role === 'admin', applied: req?.query?.applied ? true : false })
    })
})

//APPROVE / DENY
app.post("/admin/applications/approve", adminMiddleware, (req, res) => {
    const id = req.body.id
    db.run(`UPDATE application SET status = 'approved' WHERE id = ?;`, [id], (err) => {
        res.redirect('/admin/applications');
    })
})
app.post("/admin/applications/deny", adminMiddleware, (req, res) => {
    const id = req.body.id
    db.run(`UPDATE application SET status = 'denied' WHERE id = ?;`, [id], (err) => {
        res.redirect('/admin/applications');
        return
    })
})
//DELETE APPLICATION
app.post("/admin/applications/delete", adminMiddleware, (req, res) => {
    const id = req.body.id
    db.run(`DELETE FROM application WHERE id = ?`, [id], (err) => {
        res.redirect('/admin/applications');
    })
})



//DOWNLOAD
app.get('/admin/applications/:id/cv', adminMiddleware, (req, res) => {
    const id = req.params.id;
    db.get("SELECT * FROM application WHERE id = ?", [id], (err, application) => {
        const filename = application.cvId;
        const filepath = path.join('./uploads', filename);
        res.download(filepath, `${application.fullname} CV.pdf`, (err) => {
            if (err) {
                res.status(500).send({ message: 'Error downloading file' });
            }
        });

    })
})

//REGISTER
app.get('/register', (req, res) => {
    res.render('register'); // Display registration form
});
app.post('/register', async (req, res) => {
    const { fullname, email, password } = req.body;

    if (!fullname || !email || !password) {
        return res.render('register', { error: 'All fields are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
        `INSERT INTO user (fullname, email, password, role) VALUES (?, ?, ?, ?)`,
        [fullname, email, hashedPassword, "user"],
        (err) => {
            console.log(err)
            if (err) {
                return res.render('register', { error: 'Gmail already exists.' });
            }
            res.redirect('/login');
        }
    );
});
//LOGIN
app.get('/login', (req, res) => {
    res.render('login');
});
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.render('login', { error: 'All fields are required.' });
    }
    db.get(
        `SELECT * FROM user WHERE email = ?`,
        [email],
        async (err, user) => {
            if (err || !user || !await bcrypt.compare(password, user.password)) {
                return res.render('login', { error: 'Invalid username or password.' });
            }
            const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, jwtSecret, {
                expiresIn: "1h",
            });
            res.cookie("token", token);
            if (user.role === 'admin') {
                res.redirect('/admin')
            } else {
                res.redirect('/my-jobs')
            }
        }
    );
});
app.post("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/");
})
//Admin
async function createAdmin() {
    const fullname = "ADMIN";
    const email = "cjaviglez123@gmail.com";
    const password = "Aa12345678*";
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
        `INSERT INTO user (fullname, email, password, role) VALUES (?, ?, ?, ?)`,
        [fullname, email, hashedPassword, "admin"],
        (err) => {
            if (err) {
                console.log(`Error creating admin: ${err}`);
            } else {
                console.log("Admin created!");
            }
        }
    );
}
//APPROVE JOBS
app.post("/admin/job-approval", adminMiddleware, (req, res) => {
    const id = req.body.id
    db.run(`UPDATE job SET isApproved = 'approved' WHERE id = ?;`, [id], (err) => {
        if (err) {
            console.log(err)
        }
        res.redirect('/admin');
    })
})


app.listen(3000)


