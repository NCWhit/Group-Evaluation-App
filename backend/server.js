const express = require('express')
const cors = require('cors')
const { v4: uuidv4 } = require('uuid')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const strSecret = 'thisIsOurSecret'
const intSalt = 10
const dbSource = "groupEvalDB"
const HTTP_PORT = 8000
const db = new sqlite3.Database(dbSource)

// Enable SQLite foreign key constraints
db.run("PRAGMA foreign_keys = ON")

const app = express()
app.use(cors())
app.use(express.json())

// Middleware to validate JWT and session
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization']
    if (!authHeader) {
        return res.status(401).json({ error: "You must have an active session to perform this function" })
    }
    const token = authHeader.split(' ')[1]
    if (!token) {
        return res.status(401).json({ error: "You must have an active session to perform this function" })
    }
    jwt.verify(token, strSecret, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: "Invalid session identifier" })
        }
        // Verify that session is still active in database
        const sessionId = decoded.sessionId
        db.get(`SELECT * FROM tblSessions WHERE sessionId = ?`, [sessionId], (err, row) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            if (!row) {
                return res.status(401).json({ error: "Session is not active" })
            }
            // Attach user info to request and proceed
            req.user = decoded
            next()
        })
    })
}

// User Registration
app.post('/register', (req, res) => {
    let strEmail = req.body.email ? req.body.email.trim().toLowerCase() : ''
    let strPassword = req.body.password || ''
    let strFirstName = req.body.firstName || req.body.firstname || ''
    let strLastName = req.body.lastName || req.body.lastname || ''
    // Validate required fields
    if (!strEmail || !strPassword || !strFirstName || !strLastName) {
        return res.status(400).json({ error: "All fields (email, password, firstName, lastName) are required" })
    }
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(strEmail)) {
        return res.status(400).json({ error: "You must provide a valid email address" })
    }
    if (!strEmail.endsWith('@tntech.edu')) {
        return res.status(400).json({ error: "Email must be a TN Tech email" })
    }
    // Password validation
    if (strPassword.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters long" })
    }
    if (!/[A-Z]/.test(strPassword)) {
        return res.status(400).json({ error: "Password must contain at least one uppercase letter" })
    }
    if (!/[a-z]/.test(strPassword)) {
        return res.status(400).json({ error: "Password must contain at least one lowercase letter" })
    }
    if (!/[0-9]/.test(strPassword)) {
        return res.status(400).json({ error: "Password must contain at least one number" })
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(strPassword)) {
        return res.status(400).json({ error: "Password must contain at least one special character" })
    }
    // Hash the password
    const hashedPassword = bcrypt.hashSync(strPassword, intSalt)
    const strUserId = uuidv4()
    // Insert new user
    const insertUserSql = `INSERT INTO tblUsers (userId, firstName, lastName, email, password) VALUES (?, ?, ?, ?, ?)`
    db.run(insertUserSql, [strUserId, strFirstName, strLastName, strEmail, hashedPassword], function(err) {
        if (err) {
            console.error(err.message)
            if (err.message.includes('UNIQUE')) {
                return res.status(400).json({ error: "An account with that email already exists" })
            }
            return res.status(500).json({ error: err.message })
        }
        // Successful registration
        res.status(201).json({ status: "success" })
    })
})

// User Login
app.post('/login', (req, res) => {
    const strEmail = req.body.email ? req.body.email.trim().toLowerCase() : ''
    const strPassword = req.body.password || ''
    if (!strEmail || !strPassword) {
        return res.status(400).json({ error: "Must provide an email and password" })
    }
    const selectUserSql = `SELECT userId, firstName, lastName, password FROM tblUsers WHERE email = ?`
    db.get(selectUserSql, [strEmail], (err, user) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!user) {
            // User not found
            return res.status(401).json({ error: "Invalid email or password" })
        }
        // Compare password hash
        const match = bcrypt.compareSync(strPassword, user.password)
        if (!match) {
            return res.status(401).json({ error: "Invalid email or password" })
        }
        // Password ok, create session
        const strSessionID = uuidv4()
        const now = new Date().toISOString()
        const insertSessionSql = `INSERT INTO tblSessions (sessionId, email, startDatetime) VALUES (?, ?, ?)`
        db.run(insertSessionSql, [strSessionID, strEmail, now], (err) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            // Generate JWT token with user info
            const payload = {
                userId: user.userId,
                email: strEmail,
                sessionId: strSessionID,
                firstName: user.firstName,
                lastName: user.lastName,
                permissions: "admin"
            }
            const strToken = jwt.sign(payload, strSecret, { expiresIn: '12h' })
            res.status(200).json({ token: strToken, firstName: user.firstName, lastName: user.lastName })
        })
    })
})

// User Logout (invalidate session)
app.post('/logout', verifyToken, (req, res) => {
    const sessionId = req.user.sessionId
    const deleteSessionSql = `DELETE FROM tblSessions WHERE sessionId = ?`
    db.run(deleteSessionSql, [sessionId], function(err) {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        res.json({ status: "success" })
    })
})

// Protected routes (must use verifyToken middleware)

// Create a new course
app.post('/courses', verifyToken, (req, res) => {
    const userId = req.user.userId
    const { courseName, courseNumber, courseSection, courseTerm, startDate, endDate } = req.body
    if (!courseName || !courseNumber || !courseSection || !courseTerm || !startDate || !endDate) {
        return res.status(400).json({ error: "All course fields are required" })
    }
    const courseId = uuidv4()
    const insertCourseSql = `INSERT INTO tblCourses (courseId, courseName, courseNumber, courseSection, courseTerm, startDate, endDate) VALUES (?, ?, ?, ?, ?, ?, ?)`
    db.run(insertCourseSql, [courseId, courseName, courseNumber, courseSection, courseTerm, startDate, endDate], function(err) {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        // Enroll the creator in the new course
        const enrollmentId = uuidv4()
        const insertEnrollSql = `INSERT INTO tblEnrollments (enrollmentId, courseId, userId) VALUES (?, ?, ?)`
        db.run(insertEnrollSql, [enrollmentId, courseId, userId], (err) => {
            if (err) {
                console.error("Course created but error enrolling creator: ", err.message)
                // Continue even if enrollment fails (course is created)
            }
            res.status(201).json({ status: "success", courseId: courseId })
        })
    })
})

// Get all courses for the logged-in user
app.get('/courses', verifyToken, (req, res) => {
    const userId = req.user.userId
    const selectCoursesSql = `
        SELECT C.courseId, C.courseName, C.courseNumber, C.courseSection, C.courseTerm, C.startDate, C.endDate
        FROM tblCourses C
        JOIN tblEnrollments E ON C.courseId = E.courseId
        WHERE E.userId = ?`
    db.all(selectCoursesSql, [userId], (err, rows) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        res.json({ courses: rows })
    })
})

// Delete a course (and associated data)
app.delete('/courses/:courseId', verifyToken, (req, res) => {
    const userId = req.user.userId
    const courseId = req.params.courseId
    // Verify user is enrolled in the course
    const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
    db.get(checkEnrollSql, [courseId, userId], (err, enrollment) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!enrollment) {
            return res.status(403).json({ error: "You do not have access to this course" })
        }
        // Cascade delete related records: group members, groups, enrollments, assessments, questions, responses
        const deleteGroupMembersSql = `DELETE FROM tblGroupMembers WHERE groupId IN (SELECT groupId FROM tblCourseGroups WHERE courseId = ?)`
        db.run(deleteGroupMembersSql, [courseId], function(err) {
            if (err) {
                console.error("Error deleting group members for course:", err.message)
            }
            const deleteGroupsSql = `DELETE FROM tblCourseGroups WHERE courseId = ?`
            db.run(deleteGroupsSql, [courseId], function(err) {
                if (err) {
                    console.error("Error deleting groups for course:", err.message)
                }
                const deleteEnrollSql = `DELETE FROM tblEnrollments WHERE courseId = ?`
                db.run(deleteEnrollSql, [courseId], function(err) {
                    if (err) {
                        console.error("Error deleting enrollments for course:", err.message)
                    }
                    // Delete all assessments and their questions/responses for this course
                    const selectAssessmentsSql = `SELECT assessmentId FROM tblAssessments WHERE courseId = ?`
                    db.all(selectAssessmentsSql, [courseId], (err, assessments) => {
                        if (err) {
                            console.error(err.message)
                            return res.status(500).json({ error: err.message })
                        }
                        const assessmentIds = assessments.map(a => a.assessmentId)
                        db.serialize(() => {
                            assessmentIds.forEach(aid => {
                                db.run(`DELETE FROM tblAssessmentResponses WHERE assessmentId = ?`, [aid])
                                db.run(`DELETE FROM tblAssessmentQuestions WHERE assessmentId = ?`, [aid])
                                db.run(`DELETE FROM tblAssessments WHERE assessmentId = ?`, [aid])
                            })
                        })
                        // Delete the course
                        const deleteCourseSql = `DELETE FROM tblCourses WHERE courseId = ?`
                        db.run(deleteCourseSql, [courseId], function(err) {
                            if (err) {
                                console.error(err.message)
                                return res.status(500).json({ error: err.message })
                            }
                            res.json({ status: "success" })
                        })
                    })
                })
            })
        })
    })
})

// Create a new group in a course
app.post('/courses/:courseId/groups', verifyToken, (req, res) => {
    const userId = req.user.userId
    const courseId = req.params.courseId
    const groupName = req.body.groupName
    if (!groupName) {
        return res.status(400).json({ error: "Group name is required" })
    }
    // Check that user is part of the course
    const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
    db.get(checkEnrollSql, [courseId, userId], (err, enrollment) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!enrollment) {
            return res.status(403).json({ error: "You do not have access to this course" })
        }
        // Insert the new group
        const groupId = uuidv4()
        const insertGroupSql = `INSERT INTO tblCourseGroups (groupId, groupName, courseId) VALUES (?, ?, ?)`
        db.run(insertGroupSql, [groupId, groupName, courseId], function(err) {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            res.status(201).json({ status: "success", groupId: groupId })
        })
    })
})

// Get all groups for a course
app.get('/courses/:courseId/groups', verifyToken, (req, res) => {
    const userId = req.user.userId
    const courseId = req.params.courseId
    // Verify user has access to the course
    const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
    db.get(checkEnrollSql, [courseId, userId], (err, enrollment) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!enrollment) {
            return res.status(403).json({ error: "You do not have access to this course" })
        }
        const selectGroupsSql = `SELECT groupId, groupName FROM tblCourseGroups WHERE courseId = ?`
        db.all(selectGroupsSql, [courseId], (err, rows) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            res.json({ groups: rows })
        })
    })
})

// Delete a group
app.delete('/groups/:groupId', verifyToken, (req, res) => {
    const userId = req.user.userId
    const groupId = req.params.groupId
    // Find the course for this group to check permission
    const findCourseSql = `SELECT courseId FROM tblCourseGroups WHERE groupId = ?`
    db.get(findCourseSql, [groupId], (err, group) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!group) {
            return res.status(404).json({ error: "Group not found" })
        }
        const courseId = group.courseId
        // Check user enrollment in that course
        const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
        db.get(checkEnrollSql, [courseId, userId], (err, enrollment) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            if (!enrollment) {
                return res.status(403).json({ error: "You do not have access to this course" })
            }
            // Delete group members first
            const deleteMembersSql = `DELETE FROM tblGroupMembers WHERE groupId = ?`
            db.run(deleteMembersSql, [groupId], function(err) {
                if (err) {
                    console.error("Error deleting group members:", err.message)
                    // proceed even if error
                }
                const deleteGroupSql = `DELETE FROM tblCourseGroups WHERE groupId = ?`
                db.run(deleteGroupSql, [groupId], function(err) {
                    if (err) {
                        console.error(err.message)
                        return res.status(500).json({ error: err.message })
                    }
                    res.json({ status: "success" })
                })
            })
        })
    })
})

// Create a new form (assessment)
app.post('/forms', verifyToken, (req, res) => {
    const userId = req.user.userId
    const { courseId, name, startDate, endDate, status, type } = req.body
    if (!courseId || !name || !startDate || !endDate || !status || !type) {
        return res.status(400).json({ error: "All form fields (courseId, name, startDate, endDate, status, type) are required" })
    }
    // Ensure user is enrolled in that course
    const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
    db.get(checkEnrollSql, [courseId, userId], (err, enrollment) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!enrollment) {
            return res.status(403).json({ error: "You do not have access to this course" })
        }
        const assessmentId = uuidv4()
        const insertAssessmentSql = `INSERT INTO tblAssessments (assessmentId, courseId, startDate, endDate, name, status, type) VALUES (?, ?, ?, ?, ?, ?, ?)`
        db.run(insertAssessmentSql, [assessmentId, courseId, startDate, endDate, name, status, type], function(err) {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            res.status(201).json({ status: "success", assessmentId: assessmentId })
        })
    })
})

// Get all forms accessible to the user
app.get('/forms', verifyToken, (req, res) => {
    const userId = req.user.userId
    const selectFormsSql = `
        SELECT A.assessmentId, A.courseId, A.startDate, A.endDate, A.name, A.status, A.type
        FROM tblAssessments A
        JOIN tblEnrollments E ON A.courseId = E.courseId
        WHERE E.userId = ?`
    db.all(selectFormsSql, [userId], (err, forms) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        res.json({ forms: forms })
    })
})

// Get a single form by ID (with questions)
app.get('/forms/:assessmentId', verifyToken, (req, res) => {
    const userId = req.user.userId
    const assessmentId = req.params.assessmentId
    const selectFormSql = `SELECT * FROM tblAssessments WHERE assessmentId = ?`
    db.get(selectFormSql, [assessmentId], (err, form) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!form) {
            return res.status(404).json({ error: "Form not found" })
        }
        // Check access via course enrollment
        const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
        db.get(checkEnrollSql, [form.courseId, userId], (err, enrollment) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            if (!enrollment) {
                return res.status(403).json({ error: "You do not have access to this form" })
            }
            // Get questions for this form
            const selectQuestionsSql = `SELECT questionId, questionType, options, questionContents FROM tblAssessmentQuestions WHERE assessmentId = ?`
            db.all(selectQuestionsSql, [assessmentId], (err, questions) => {
                if (err) {
                    console.error(err.message)
                    return res.status(500).json({ error: err.message })
                }
                // Format options from JSON string to array
                const formattedQuestions = questions.map(q => {
                    let opts = []
                    if (q.options) {
                        try {
                            opts = JSON.parse(q.options)
                        } catch {
                            opts = q.options.split(',').map(s => s.trim())
                        }
                    }
                    return {
                        questionId: q.questionId,
                        questionType: q.questionType,
                        questionContents: q.questionContents,
                        options: opts
                    }
                })
                form.questions = formattedQuestions
                res.json({ form: form })
            })
        })
    })
})

// Update a form
app.put('/forms/:assessmentId', verifyToken, (req, res) => {
    const userId = req.user.userId
    const assessmentId = req.params.assessmentId
    // Verify form exists and user has access
    const selectFormSql = `SELECT * FROM tblAssessments WHERE assessmentId = ?`
    db.get(selectFormSql, [assessmentId], (err, form) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!form) {
            return res.status(404).json({ error: "Form not found" })
        }
        const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
        db.get(checkEnrollSql, [form.courseId, userId], (err, enrollment) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            if (!enrollment) {
                return res.status(403).json({ error: "You do not have access to this form" })
            }
            // Build update query dynamically
            const { name, startDate, endDate, status, type } = req.body
            let fields = []
            let params = []
            if (name) { fields.push("name = ?"); params.push(name) }
            if (startDate) { fields.push("startDate = ?"); params.push(startDate) }
            if (endDate) { fields.push("endDate = ?"); params.push(endDate) }
            if (status) { fields.push("status = ?"); params.push(status) }
            if (type) { fields.push("type = ?"); params.push(type) }
            if (fields.length === 0) {
                return res.status(400).json({ error: "No fields provided to update" })
            }
            const updateSql = `UPDATE tblAssessments SET ${fields.join(', ')} WHERE assessmentId = ?`
            params.push(assessmentId)
            db.run(updateSql, params, function(err) {
                if (err) {
                    console.error(err.message)
                    return res.status(500).json({ error: err.message })
                }
                res.json({ status: "success" })
            })
        })
    })
})

// Delete a form
app.delete('/forms/:assessmentId', verifyToken, (req, res) => {
    const userId = req.user.userId
    const assessmentId = req.params.assessmentId
    const selectFormSql = `SELECT * FROM tblAssessments WHERE assessmentId = ?`
    db.get(selectFormSql, [assessmentId], (err, form) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!form) {
            return res.status(404).json({ error: "Form not found" })
        }
        // Check user access via course enrollment
        const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
        db.get(checkEnrollSql, [form.courseId, userId], (err, enrollment) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            if (!enrollment) {
                return res.status(403).json({ error: "You do not have access to this form" })
            }
            // Delete all responses for this form
            db.run(`DELETE FROM tblAssessmentResponses WHERE assessmentId = ?`, [assessmentId], function(err) {
                if (err) {
                    console.error("Error deleting form responses:", err.message)
                }
                // Delete all questions for this form
                db.run(`DELETE FROM tblAssessmentQuestions WHERE assessmentId = ?`, [assessmentId], function(err) {
                    if (err) {
                        console.error("Error deleting form questions:", err.message)
                    }
                    // Delete the form itself
                    db.run(`DELETE FROM tblAssessments WHERE assessmentId = ?`, [assessmentId], function(err) {
                        if (err) {
                            console.error(err.message)
                            return res.status(500).json({ error: err.message })
                        }
                        res.json({ status: "success" })
                    })
                })
            })
        })
    })
})

// Create a new question for a form
app.post('/forms/:assessmentId/questions', verifyToken, (req, res) => {
    const userId = req.user.userId
    const assessmentId = req.params.assessmentId
    const { questionType, questionContents, options } = req.body
    if (!questionType || !questionContents) {
        return res.status(400).json({ error: "Question type and contents are required" })
    }
    // Check that the form exists and user has access
    const selectFormSql = `SELECT * FROM tblAssessments WHERE assessmentId = ?`
    db.get(selectFormSql, [assessmentId], (err, form) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!form) {
            return res.status(404).json({ error: "Form not found" })
        }
        const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
        db.get(checkEnrollSql, [form.courseId, userId], (err, enrollment) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            if (!enrollment) {
                return res.status(403).json({ error: "You do not have access to this form" })
            }
            // Prepare options for storage
            let optionsStr = null
            if (options && Array.isArray(options)) {
                optionsStr = JSON.stringify(options)
            } else if (options && typeof options === 'string') {
                optionsStr = JSON.stringify(options.split(',').map(o => o.trim()))
            }
            const questionId = uuidv4()
            const insertQuestionSql = `INSERT INTO tblAssessmentQuestions (questionId, assessmentId, questionType, options, questionContents) VALUES (?, ?, ?, ?, ?)`
            db.run(insertQuestionSql, [questionId, assessmentId, questionType, optionsStr, questionContents], function(err) {
                if (err) {
                    console.error(err.message)
                    return res.status(500).json({ error: err.message })
                }
                res.status(201).json({ status: "success", questionId: questionId })
            })
        })
    })
})

// Get all questions for a form
app.get('/forms/:assessmentId/questions', verifyToken, (req, res) => {
    const userId = req.user.userId
    const assessmentId = req.params.assessmentId
    const selectFormSql = `SELECT * FROM tblAssessments WHERE assessmentId = ?`
    db.get(selectFormSql, [assessmentId], (err, form) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!form) {
            return res.status(404).json({ error: "Form not found" })
        }
        const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
        db.get(checkEnrollSql, [form.courseId, userId], (err, enrollment) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            if (!enrollment) {
                return res.status(403).json({ error: "You do not have access to this form" })
            }
            const selectQuestionsSql = `SELECT questionId, questionType, options, questionContents FROM tblAssessmentQuestions WHERE assessmentId = ?`
            db.all(selectQuestionsSql, [assessmentId], (err, rows) => {
                if (err) {
                    console.error(err.message)
                    return res.status(500).json({ error: err.message })
                }
                const questions = rows.map(q => {
                    let opts = []
                    if (q.options) {
                        try {
                            opts = JSON.parse(q.options)
                        } catch {
                            opts = q.options.split(',').map(s => s.trim())
                        }
                    }
                    return {
                        questionId: q.questionId,
                        questionType: q.questionType,
                        questionContents: q.questionContents,
                        options: opts
                    }
                })
                res.json({ questions: questions })
            })
        })
    })
})

// Update a question
app.put('/questions/:questionId', verifyToken, (req, res) => {
    const userId = req.user.userId
    const questionId = req.params.questionId
    const { questionType, questionContents, options } = req.body
    // Find question and associated course via its form
    const query = `
        SELECT A.courseId as courseId
        FROM tblAssessmentQuestions Q
        JOIN tblAssessments A ON Q.assessmentId = A.assessmentId
        WHERE Q.questionId = ?`
    db.get(query, [questionId], (err, row) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!row) {
            return res.status(404).json({ error: "Question not found" })
        }
        // Verify user access to that course
        const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
        db.get(checkEnrollSql, [row.courseId, userId], (err, enrollment) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            if (!enrollment) {
                return res.status(403).json({ error: "You do not have access to this question" })
            }
            // Build update fields
            let fields = []
            let params = []
            if (questionType) {
                fields.push("questionType = ?")
                params.push(questionType)
            }
            if (questionContents) {
                fields.push("questionContents = ?")
                params.push(questionContents)
            }
            if (options !== undefined) {
                let optionsStr = null
                if (options && Array.isArray(options)) {
                    optionsStr = JSON.stringify(options)
                } else if (options && typeof options === 'string') {
                    optionsStr = JSON.stringify(options.split(',').map(o => o.trim()))
                } else {
                    optionsStr = null
                }
                fields.push("options = ?")
                params.push(optionsStr)
            }
            if (fields.length === 0) {
                return res.status(400).json({ error: "No fields provided to update" })
            }
            const updateSql = `UPDATE tblAssessmentQuestions SET ${fields.join(', ')} WHERE questionId = ?`
            params.push(questionId)
            db.run(updateSql, params, function(err) {
                if (err) {
                    console.error(err.message)
                    return res.status(500).json({ error: err.message })
                }
                res.json({ status: "success" })
            })
        })
    })
})

// Delete a question
app.delete('/questions/:questionId', verifyToken, (req, res) => {
    const userId = req.user.userId
    const questionId = req.params.questionId
    const query = `
        SELECT A.courseId as courseId
        FROM tblAssessmentQuestions Q
        JOIN tblAssessments A ON Q.assessmentId = A.assessmentId
        WHERE Q.questionId = ?`
    db.get(query, [questionId], (err, row) => {
        if (err) {
            console.error(err.message)
            return res.status(500).json({ error: err.message })
        }
        if (!row) {
            return res.status(404).json({ error: "Question not found" })
        }
        // Verify user has access to that course
        const checkEnrollSql = `SELECT * FROM tblEnrollments WHERE courseId = ? AND userId = ?`
        db.get(checkEnrollSql, [row.courseId, userId], (err, enrollment) => {
            if (err) {
                console.error(err.message)
                return res.status(500).json({ error: err.message })
            }
            if (!enrollment) {
                return res.status(403).json({ error: "You do not have access to this question" })
            }
            // Delete any responses for this question, then delete the question
            db.run(`DELETE FROM tblAssessmentResponses WHERE questionId = ?`, [questionId], function(err) {
                if (err) {
                    console.error("Error deleting question responses:", err.message)
                }
                db.run(`DELETE FROM tblAssessmentQuestions WHERE questionId = ?`, [questionId], function(err) {
                    if (err) {
                        console.error(err.message)
                        return res.status(500).json({ error: err.message })
                    }
                    res.json({ status: "success" })
                })
            })
        })
    })
})

// Start server
app.listen(HTTP_PORT, () => {
    console.log(`Server running on port ${HTTP_PORT}`)
})
