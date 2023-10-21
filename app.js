const express = require('express');
const app=express()
const path=require('path')
const userRouter=require('./routers/user')
const User=require('./models/userSchema')
const session = require('express-session');
const db=require('./config/db')
const flash=require("express-flash");
const cookieParser = require('cookie-parser');

require('dotenv').config()


  
app.use(flash());
app.use(express.static("public"))

app.use(express.json())
app.use(express.urlencoded({extended:true}))

app.set("views",path.join(__dirname,'views'))
app.set('view engine','ejs')

app.use((req, res, next) => {
  res.header('Cache-Control', 'private, no-store, no-cache, must-revalidate, max-age=0');
  next();
});

app.use(
  session({
    secret:process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(cookieParser())


app.use('/',userRouter)



const PORT=process.env.PORT

app.listen(PORT,()=>{
    console.log(`Connected SuccessFully on Port http://localhost:${PORT}`)
})