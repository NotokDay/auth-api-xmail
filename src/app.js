const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const jwt = require('jsonwebtoken')
const db = require('./config/db.config');
const { hash: hashPassword, compare: comparePassword } = require('./utils/password');
const { generate: generateToken } = require('./utils/token');


const authRoute = require('./routes/auth.route');

const { httpLogStream } = require('./utils/logger');
const { sendEmail } = require('./mailSender');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(morgan('dev'));
app.use(morgan('combined', { stream: httpLogStream }));
app.use(cors());

app.use('/api/auth', authRoute);

app.get('/', (req, res) => {
    res.status(200).send({
        status: "success",
        data: {
            message: "API working fine"
        }
    });
});

// Email verification route
app.get('/api/auth/verify/:token', async (req, res) => {
    try {
		const { token } = req.params;
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY)
        //console.log(decoded)
        
        // Update the user's isVerified field in the database
        updateIsVerifiedToTrueQuery = "UPDATE users SET is_verified = 1 WHERE email = ?"
        db.query(updateIsVerifiedToTrueQuery, [decoded.email], (err, res) => {
            if(err) console.log(err)
            //console.log('user is validated')
        })
        return res.status(200).send(
            {status: "success", message: "Your email address is verified."}
        )
	} catch (e) {
		if (e instanceof jwt.JsonWebTokenError) {
			// if the error thrown is because the JWT is unauthorized, return a 401 error
            //console.log('jwt is not verified')
            return res.status(401).send({
                status: "error",
                message: "The link is not valid."
            })
		}
		// otherwise, return a bad request error
		return res.status(400).send({
            status: "error",
            message: "Something went wrong. Please try again. "
        })
	}

});

app.post("/api/auth/changepassword", async (req, res) => {
    try {
        //oldpassword, newpassword, confirmpassword
        const { token, oldPassword, newPassword, confirmPassword } = req.body;
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY)
        
        const getUserFromDB = "SELECT * FROM users WHERE id = ?"
        db.query(getUserFromDB, [decoded.id], (err, dbRes) => {
            if(err){
                return res.status(500).send({
                    status: "error", 
                    message: err.message
                })
            }
            if (comparePassword(oldPassword.trim(), dbRes[0].password)) {
                if(oldPassword === newPassword){
                    return res.send({
                        status: "error",
                        message: "Your new password cannot be the same as your old password."
                    })
                }
                if(newPassword != confirmPassword){
                    return res.send({
                        status: "error",
                        message: "Passwords do not match."
                    })
                }
                //change user's password
                const hashedPassword = hashPassword(newPassword.trim())
                const changePassword = "UPDATE users SET password=? WHERE id=?"
                db.query(changePassword, [hashedPassword,decoded.id], (err, dbResForPassChange) => {
                    if(err){
                        return res.status(500).send({
                            status: "error",
                            message: err.message
                        })
                    }

                    const token = generateToken(decoded.id);
                    return res.status(200).send({
                        status: 'success',
                        data: {
                            token,
                            firstname: dbRes[0].firstname,
                            lastname: dbRes[0].lastname,
                            email: dbRes[0].email
                        }
                });
            })}
            else{
                return res.status(401).send({
                    status: 'error',
                    message: 'Incorrect password'
                });
            }
        })
        
        
	} catch (e) {
		if (e instanceof jwt.JsonWebTokenError) {
			// if the error thrown is because the JWT is unauthorized, return a 401 error
            //console.log('jwt is not verified')
            return res.status(401).send({
                status: "error",
                message: "The link is not valid."
            })
		}
		// otherwise, return a bad request error
		return res.status(400).send({
            status: "error",
            message: "Bad request."
        })
	}
})


app.post("/api/auth/resetpassword", async (req, res) => {
    try {
        
        const { email, otp, newPassword, confirmPassword } = req.body;

        const getUser = "SELECT * FROM users WHERE email = ?"
        const user = await new Promise((resolve, reject) => {
            db.query(getUser, [email], (err, result) => {
                if (err) {
                    reject(err)
                }
                resolve(result)
            });
        });

        const query = "SELECT * FROM otps WHERE email = ? AND otp = ? AND expires_at > NOW()";
            db.query(query, [user[0].email, otp], (err, result) => {
                if (err) {
                    return res.status(500).send({
                        status: "error", 
                        message: err.message
                    })
                } 
                //otp is still ok
                if (result.length > 0) {
                    if(newPassword != confirmPassword){
                        console.log(newPassword, confirmPassword)
                        return res.status(400).send({
                            status: "error",
                            message: "Passwords do not match."
                        })
                    }
                    //change user's password
                    console.log('we are here')
                    const hashedPassword = hashPassword(newPassword.trim())
                    const changePassword = "UPDATE users SET password=? WHERE id=?"
                    db.query(changePassword, [hashedPassword,user[0].id], (err, dbResForPassChange) => {
                        if(err){
                            return res.status(500).send({
                                status: "error",
                                message: err.message
                            })
                        }

                        //everything is ok. But before sending new creds, clear otp table
                        const query = "DELETE FROM otps WHERE email = ?";
                        db.query(query, [user[0].email],(err, clearResult) => {
                        if (err) {
                            console.log("Cannot delete old otps. Something went wrong.")
                            console.log(err)
                        } else {
                            console.log("User's past otps deleted.")
                        }
                        });
    
                        // const token = generateToken(user[0].id);
                        return res.status(200).send({
                            status: 'success',
                            message: "Password reset successful"
                    });
                })
                } else {
                    return res.status(403).send({
                        status: "error",
                        message: "OTP is not valid"
                    })
                }
            });
        
         
	} catch (e) {
		if (e instanceof jwt.JsonWebTokenError) {
			// if the error thrown is because the JWT is unauthorized, return a 401 error
            //console.log('jwt is not verified')
            return res.status(401).send({
                status: "error",
                message: "The link is not valid."
            })
		}
		// otherwise, return a bad request error
		return res.status(400).send({
            status: "error",
            message: "Bad request."
        })
	}
})
  

function generateOTP(length = 6) {
    const otp = Array.from({ length }, () => Math.floor(Math.random() * 10)).join('');
    return otp;
}


app.get("/api/auth/reset/:encodedEmail", async (req, res) => {
    try {
		const { encodedEmail } = req.params;
        
        const email = Buffer.from(encodedEmail, 'base64').toString()
        
        const getUser = "SELECT * FROM users WHERE email = ?"
        const dbRes = await new Promise((resolve, reject) => {
            db.query(getUser, [email], (err, result) => {
                if (err) {
                    reject(err)
                }
                resolve(result)
            });
        });
        const otp = generateOTP();
        const expiresIn = 10 * 60 * 1000; // 10 minutes
        const expiresAt = new Date(Date.now() + expiresIn);

        const query = "INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)";
        try{
            db.query(query, [dbRes[0].email, otp, expiresAt], (err, dbResult) => {
            if (err) {
                return res.status(500).send({
                    status: "error", 
                    message: "Invalid link"
                })
            } else {
                sendEmail(dbRes[0].email, action="reset", otp) 
                return res.status(200).send({
                    status: "success",
                    message: "An OTP code was sent to your email address."
                })
            }
            });
        } catch (err){
            return res.status(500).send({
                status: "error", 
                message: "Invalid link"
            })
        }
	} catch (e) {
		if (e instanceof jwt.JsonWebTokenError) {
			// if the error thrown is because the JWT is unauthorized, return a 401 error
            //console.log('jwt is not verified')
            return res.status(401).send({
                status: "error",
                message: "The link is not valid."
            })
		}
		// otherwise, return a bad request error
		return res.status(400).send({
            status: "error",
            message: e.message
        })
	}

})


app.get('/api/auth/change/:token', async(req, res) => {
    try {
		const { token } = req.params;
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY)
        const getUser = "SELECT email FROM users WHERE id = ?"
        db.query(getUser, [decode.id], (err, dbRes) => {
            if(err)
                return res.status(500).send({
                status: "error", 
                message: err.message
            })

            sendEmail(dbRes[0].email, action="reset")
        })
        
        
	} catch (e) {
		if (e instanceof jwt.JsonWebTokenError) {
			// if the error thrown is because the JWT is unauthorized, return a 401 error
            //console.log('jwt is not verified')
            return res.status(401).send({
                status: "error",
                message: "The link is not valid."
            })
		}
		// otherwise, return a bad request error
		return res.status(400).send({
            status: "error",
            message: "Something went wrong. Please try again. "
        })
	}
})

app.use((err, req, res, next) => {
    res.status(err.statusCode || 500).send({
        status: "error",
        message: err.message
    });
    next();
});

module.exports = app;