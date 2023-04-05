const User = require('../models/user.model');
const { hash: hashPassword, compare: comparePassword } = require('../utils/password');
const { generate: generateToken } = require('../utils/token');
const { sendEmail } = require('../mailSender')
const db = require('../config/db.config');

exports.signup = (req, res) => {
    const { firstname, lastname, email, password } = req.body;
    const hashedPassword = hashPassword(password.trim());

    const user = new User(firstname.trim(), lastname.trim(), email.trim(), hashedPassword);

    //create the user 
    User.create(user, (err, data) => {
        if (err) {
            res.status(500).send({
                status: "error",
                message: err.message
            });
        } else {
            const token = generateToken(data.id);
            res.status(201).send({
                status: "success",
                data: "Verification link is sent to your email. Please check your inbox."
            });
        }
    });

    //send email to the user
    sendEmail(email)
    
};

exports.signin = (req, res) => {
    const { email, password } = req.body;
    User.findByEmail(email.trim(), (err, data) => {
        if (err) {
            if (err.kind === "not_found") {
                res.status(404).send({
                    status: 'error',
                    message: `User was not found`
                });
                return;
            }
            res.status(500).send({
                status: 'error',
                message: err.message
            });
            return;
        }
        if (data) {
            //check if the user is verified
            const checkIfUserVerified = "SELECT is_verified FROM users WHERE email = ?"
            db.query(checkIfUserVerified, [email], (err, dbRes) => {
                if(err) {
                    res.status(500).send({
                        status: 'error',
                        message: err.message
                    });
                    return;
                }
                if(dbRes[0].is_verified){
                    if (comparePassword(password.trim(), data.password)) {
                        const token = generateToken(data.id);
                        res.status(200).send({
                            status: 'success',
                            data: {
                                token,
                                firstname: data.firstname,
                                lastname: data.lastname,
                                email: data.email
                            }
                        });
                        return;
                    }
                    res.status(401).send({
                        status: 'error',
                        message: 'Incorrect password'
                    });
                    return;
                }
                res.status(401).send({
                    status: "error",
                    message: "Please verify your email address."
                })
            })
        }
    });

}