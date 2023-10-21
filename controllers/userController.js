
const User = require('../models/userSchema')
const bcrypt = require('bcrypt')
const nodemailer = require('nodemailer');
const jwt = require("jsonwebtoken");
const flash = require("express-flash")
const crypto = require("crypto")
const otpFunctions = require('../utility/otpFunctions')
const OTP = require('../models/otpSchema')
const session = require('express-session');
module.exports = {
    initial: (req, res) => {
        try {
            res.render('./user/landingpage');
        } catch (error) {
            console.log(error);
        }

    },
    home: (req, res) => {
        try {
            res.render("user/homepage", {user: req.session.user});
        } catch (error) {
            console.log(error);
        }
    },

    login: (req, res) => {
        res.render('./user/login', { error: req.session.error });
    },

    userlogin: async (req, res) => {
        try {
            // Attempt to find a user in the database based on the provided email.
            const user = await User.findOne({ Email: req.body.Email });

            // Check if the user's status is "Active" before proceeding.
            if (user.Status === "Active") {
                // Check if a user was found with the provided email.
                if (user) {
                    // Compare the provided password with the stored hashed password.
                    const passwordMatch = await bcrypt.compare(
                        req.body.Password,
                        user.Password
                    );

                    // If the passwords match, create a JSON Web Token (JWT).
                    if (passwordMatch) {
                        const accessToken = jwt.sign(
                            { user: user._id },
                            process.env.ACCESS_TOKEN_SECRET,
                            { expiresIn: 60 * 60 }
                        );

                        // Set the JWT as a cookie.
                        res.cookie("userJwt", accessToken, { maxAge: 60 * 1000 * 60 });

                        // Store user information in the session.
                        req.session.user = user;

                        // Redirect to the user's homepage.
                        res.redirect("/homepage");
                    } else {
                        // If passwords don't match, show an error and redirect to the login page.
                        req.flash("error", "invalid username or password");
                        res.redirect("/login");
                    }
                } else {
                    // If no user is found, show an error and redirect to the login page.
                    req.flash("error", "invalid username or password");
                    res.redirect("/login");
                }
            } else {
                // If the user's status is not "Active," show an error and redirect to the login page.
                req.flash("error", "You have been banned");
                res.redirect("/login");
            }
        } catch (error) {
            // Handle any errors that occur during the process.
            console.log(error);
            req.flash("error", "invalid username or password");
            res.redirect("/login");
        }
    },

    signup: (req, res) => {
        // if (req.session.auth) {
        //     res.redirect("/dashboard");
        // } else {
        //     res.render("user/signup", { err: "" });
        // }
        res.render("user/signup", { err: "" });
    },

    postUserSignup: async (req, res) => {
        try {
            const salt = await bcrypt.genSalt();
            req.body.Password = await bcrypt.hash(req.body.Password, salt);
            req.body.confirmPassword = await bcrypt.hash(req.body.confirmPassword, salt);

            const user = req.body;
            const Email = req.body.Email;

            const emailRegex = /^([a-zA-Z0-9\._]+)@([a-zA-Z0-9]+).([a-z]+)(.[a-z]+)?$/;

            //testing the eamil

            const isValidemail = emailRegex.test(Email);

            if (req.body.Password === req.body.confirmPassword) {
                if (isValidemail) {
                    req.session.user = req.body
                    const existingUser = await User.findOne({ Email: req.body.Email });
                    if (existingUser) {
                        req.flash("error", "Email already Exist");
                        console.log("email already there")
                        res.redirect("/signup");
                    } else {
                        otpToBeSent = otpFunctions.generateOTP();
                        const result = otpFunctions.sendOTP(req, res, Email, otpToBeSent);
                    }
                } else {
                    res.redirect('/signup');
                    console.log("invalid email address")
                }
            } else {
                req.flash("error", "Password Doesn't Match");
                res.redirect("/signup");
            }

        } catch (error) {
            console.error(error);
            res.redirect("/signup");
        }
    },

    getemailVerification: async (req, res) => {
        try {
            // email is taken from the input 
            const Email = req.session.user.Email;

            // a timeout function to deleted the old otp after 1 minute
            setTimeout(() => {
                OTP.deleteOne({ Email: Email })
                    .then(() => {
                        console.log("Document deleted successfully");
                    })
                    .catch((err) => {
                        console.error(err);
                    });
            }, 60000);
            res.render("user/emailVerification", { messages: req.flash() });
        } catch (error) {
            console.log(error);
            res.redirect("/signup");
        }
    },

    postEmailVerification: async (req, res) => {
        try {
            const userData = await User.create(req.session.user);
            if (userData) {
                const accessToken = jwt.sign(
                    { user: userData._id },
                    process.env.ACCESS_TOKEN_SECRET,
                    { expiresIn: 60 * 60 }
                );

                // Set the cookie before sending any response
                res.cookie("userjwt", accessToken, { maxAge: 60 * 1000 * 60 });

                // Then redirect to the ajax
                // res.redirect('/homepage');
                res.json({ success: true })

            } else {
                req.flash("error", "Invalid Email Address");
                console.log("Invalid Email Address");
                res.redirect('/signup');
            }
        } catch (error) {
            console.error(error);
            res.redirect('/signup');
        }
    },

    otpAuth: async (req, res, next) => {
        try {
            const { otp } = req.body;
            const Email = req.session.user.Email;

            console.log("User-provided OTP:", otp);
            console.log("Email:", Email);

            // Check for an OTP record in the database
            const matchedOTPrecord = await OTP.findOne({
                Email: Email,
            })

            console.log("Matched OTP record from the database:", matchedOTPrecord);

            if (!matchedOTPrecord) {
                throw new Error("No OTP records found for the provided email.");
            }

            const { expiresAt } = matchedOTPrecord;
            console.log("Expires At:", expiresAt);

            if (expiresAt) {
                if (expiresAt < Date.now()) {
                    await OTP.deleteOne({ Email: Email });
                    throw new Error("The OTP code has expired. Please request a new one.");
                }
            } else {
                console.log("ExpiresAt is not defined in the OTP record.");
            }

            console.log("Stored OTP from the database:", matchedOTPrecord.otp);

            if (Number(otp) === matchedOTPrecord.otp) {
                req.session.OtpValid = true;
                // res.json({success:true})
                next();
            } else {
                console.log("Entered OTP does not match stored OTP.");
                req.flash("error", "Invalid OTP. Please try again.");
                res.redirect("/emailVerification");
            }
        } catch (error) {
            console.error(error);
            res.redirect("/emailverification");
        }
    },

    resendOtp: async (req, res) => {
        try {
            const duration = 60;
            const Email = req.session.user.Email;
            otpToBeSent = otpFunctions.generateOTP();
            console.log(otpToBeSent);
            const result = otpFunctions.resendOTP(req, res, Email, otpToBeSent);
        } catch (error) {
            console.log(error);
            req.flash("error", "error sending OTP");
            res.redirect("/emailVerification");
        }
    },

    forgotpassword: (req, res) => {
        res.render("user/forgotPassword", {
            messages: req.flash(),

        });
    },
    postforgotpassword: async (req, res) => {
        try {
            req.session.Email = req.body.Email;
            const Email = req.body.Email;
            console.log("1223",Email)
            const userData = await User.findOne({ Email: Email });
            if (userData) {
                otpToBeSent = otpFunctions.generateOTP();
                const result = otpFunctions.passwordsendOTP(req, res, Email, otpToBeSent);

            } else {
                req.flash("error", "Email Not Registesred");
                res.redirect("/otpVerification")
            }
        } catch (error) {
            console.log(error);
            res.redirect("/login")
        }
    },

    PasswordResendOtp: async (req, res) => {
        try {
            const duration = 60;
            const Email = req.session.Email;
            console.log("resend email is ",Email);
            otpToBeSent = otpFunctions.generateOTP();
            console.log(otpToBeSent);
            const result = otpFunctions.passwordresendOTP(req, res, Email, otpToBeSent);
        } catch (error) {
            console.log(error);
            req.flash("error", "Error sending OTP");
            res.redirect("/forgotpassword");
        }
    },

    getOtpVerification: async (req, res) => {
        try {
            // email is taken from the input 
            const Email = req.session.Email;
            console.log("this is new eamil",Email);
            // a timeout function to deleted the old otp after 1 minute
            setTimeout(() => {
                OTP.deleteOne({ Email: Email })
                    .then(() => {
                        console.log("Document deleted successfully");
                    })
                    .catch((err) => {
                        console.error(err);
                    });
            }, 60000);
            res.render("user/otpVerification", { messages: req.flash() });
        } catch (error) {
            console.log(error);
            res.redirect("/login");
        }
    },
    passwordOtpAuth: async (req, res,next) => {
        try {
           
            let { otp } = req.body;

            // Ensure an OTP record exists for the email
               console.log(req.session.Email);
              const matchedOTPrecord = await OTP.findOne({
           Email: req.session.Email,
            });

            if (!matchedOTPrecord) {
                throw new Error("No OTP records found for the provided email.");
            }

            const { expiresAt } = matchedOTPrecord;
            console.log("Expires At:", expiresAt);

            if (expiresAt) {
                if (expiresAt < Date.now()) {
                    await OTP.deleteOne({ Email: Email });
                    throw new Error("The OTP code has expired. Please request a new one.");
                }
            } else {
                console.log("ExpiresAt is not defined in the OTP record.");
            }

            console.log("Stored OTP from the database:", matchedOTPrecord.otp);

            if (Number(otp) === matchedOTPrecord.otp) {
                req.session.OtpValid = true;
                next();
            } else {
                console.log("Entered OTP does not match stored OTP.");
                req.flash("error", "Invalid OTP. Please try again.");
                res.redirect("/otpVerification");
            }
        } catch (error) {
            console.error(error);
            res.redirect("/login");
        }
    },

    postOtpVerification: async (req, res) => {
        try {
            res.json({ success: true })
            // res.redirect('/createNewPassword')
        } catch (error) {
            console.log(error);
            res.redirect("/login");
        }
    },

    getCreateNewPassword: async (req, res) => {
        res.render('user/changePassword')
    },

    postCreateNewPassword: async (req, res) => {
        try {
            const user = await User.findOne({ Email: req.session.Email })
            if (req.body.Password === req.body.confirmPassword) {
                const hashedPassword = await bcrypt.hash(req.body.Password, 8);
                const updatedUser = await User.updateOne({ _id: user._id },{ $set: { Password: hashedPassword } });
                console.log(hashedPassword);
                if(!updatedUser){
                    throw new Error('Error updating password');
                    }
                    const accessToken = jwt.sign(
                      { user: user._id },
                      process.env.ACCESS_TOKEN_SECRET,
                      { expiresIn: 60 * 60 }
                    );
                    res.cookie("userJwt", accessToken, { maxAge: 60 * 1000 * 60 });
                    req.session.user = user;
                    res.redirect("/homepage");

            } else {
                req.flash("error", "Passwords do not match!");
                res.redirect('/createNewPassword');
            }
        } catch (error) {
            console.log(error);
            res.redirect("/login");
        }
    },
 
    getUserLogout: (req, res) => {
        req.session.user = false;
        res.clearCookie("userJwt");
        res.redirect("/login");
    },

};

