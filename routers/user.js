const express=require('express')
const router=express.Router()
const userController=require('../controllers/userController')


router.route('/')
.get(userController.initial)

router.route('/homepage')
.get(userController.home)

router.route('/login')
.get(userController.login)
.post(userController.userlogin)

router.route('/forgotpassword')
.get(userController.forgotpassword)
.post(userController.postforgotpassword)

router.route('/otpVerification')
.get(userController.getOtpVerification)
.post(userController.passwordOtpAuth,userController.postOtpVerification)

router.route('/passwordResendOtp')
.get(userController.PasswordResendOtp)

router.route('/createNewPassword')
.get(userController.getCreateNewPassword)
.post(userController.postCreateNewPassword)

router.route('/signup')
.get(userController.signup)
.post(userController.postUserSignup)

router.route('/emailVerification')
.get(userController.getemailVerification)
.post(userController.otpAuth,userController.postEmailVerification)

router.route('/resendOtp')
.get(userController.resendOtp)
.post(userController.otpAuth)

router.route('/logout')
.get(userController.getUserLogout)

module.exports=router;