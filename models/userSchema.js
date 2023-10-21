const mongoose=require('mongoose')
const Schema=mongoose.Schema

const Userschema=new Schema({
    Username:{type:String},
    Email:{type:String,required:true},
    Password:{type:String,required:true},
    Status:{type:String,default:'Active'},

Address: [{
    Name: {type: String},
    AddressLane: { type: String },
    City: { type: String },
    Pincode: { type: Number },
    State: { type: String },
    Mobile: { type: Number },
 }],
});
const User =  mongoose.model('User', Userschema);
module.exports = User