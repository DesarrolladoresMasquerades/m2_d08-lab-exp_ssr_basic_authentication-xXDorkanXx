const express = require('express');
const User = require('../models/User.model');
const router = express.Router();
const saltRounds = 5;
const bcrypt = require('bcrypt');
const res = require('express/lib/response');

router.route('/signup')
.get((req, res) => {
	res.render('signup');
})
.post((req, res)=>{
	const username = req.body.username;
	let password = req.body.password;

	if(!username || !password) res.render("signup", {errorMessage: "All fields are required"});

	User.findOne({username})
	.then(user=>{
		if(user && user.username){
			throw new Error("User already taken!")
		};
		
		const salt = bcrypt.genSaltSync(saltRounds);
		password = bcrypt.hashSync(password, salt);

		User.create({username, password})
		.then(()=>{res.render("index", {signupMessage: "You sign up succefully!"})})
		.catch((err)=>{
			console.log(err);
			res.redirect("/auth/signup")})
	})
	.catch((err)=>{
		res.render("signup", {errorMessage: err});
	})
});

module.exports = router;