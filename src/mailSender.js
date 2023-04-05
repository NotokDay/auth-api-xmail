const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv/config');

const transporter = nodemailer.createTransport({
    service: "gmail",
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_APP_PASSOWRD,
    },
});

const sendEmail = (userEmailAddress, action="validation", otp=0) => {
    const token = jwt.sign({
		email: userEmailAddress
	}, process.env.JWT_SECRET_KEY, { expiresIn: '60m' });

    emailSubject = 'Email Verification'
    emailContent = `Hi! You have recently registered in our platform.
    Please follow the given link to verify your email:
    http://localhost:443/api/auth/verify/${token}
    
    Thanks!`

    if(action === "reset"){
        emailSubject = "Reset your password"
        emailContent = `Here's your one time password:
        ${otp}`
    }

    const mailConfigurations = {
        from: 'xmail.validation@gmail.com',
        to: userEmailAddress,
        subject: emailSubject,
        text: emailContent
    };	
    transporter.sendMail(mailConfigurations, function(error, info){
        if (error) throw Error(error);
        console.log('Email Sent Successfully');
        //console.log(info);
    });

}

module.exports = {sendEmail}




