const User = require('../models/user.model');
const { hash: hashPassword, compare: comparePassword } = require('../utils/password');
const { generate: generateToken } = require('../utils/token');
const { sendEmail } = require('../mailSender')
const db = require('../config/db.config');
const axios = require('axios');


const url = 'https://email-checker.p.rapidapi.com/verify/v1';

const getEmail = async (email) => {
    //const email = 'your_email@example.com'; // Replace this with your desired email input method

    const querystring = {
        email: email,
    };

    const headers = {
        'X-RapidAPI-Key': 'ee007d9eddmshde6e8d7f4318d2ep170771jsn3a8e621efd10',
        'X-RapidAPI-Host': 'email-checker.p.rapidapi.com',
    };

    try {
        const response = await axios.get(url, { headers: headers, params: querystring });
        console.log(response.data)
        if(response.data.status === "valid") return 1
        else return 0
    } catch (error) {
        console.log(error)
        return 0
    }
};



exports.signup = async (req, res) => {
    const { firstname, lastname, email, password } = req.body;
    const hashedPassword = hashPassword(password.trim());

    const user = new User(firstname.trim(), lastname.trim(), email.trim(), hashedPassword);

    if(await getEmail(email) === 1){
    //create the user 
        User.create(user, (err, data) => {
            if (err) {
                res.status(500).send({
                    status: "error",
                    message: err.message
                });
            } else {
                    res.status(201).send({
                        status: "success",
                        data: "Verification link is sent to your email. Please check your inbox."
                    });
                    sendEmail(email)
            }
        });
        return
    }

    return res.status(400).send({
        status: "error",
        data: "The email address is not a valid email."
    });
    
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