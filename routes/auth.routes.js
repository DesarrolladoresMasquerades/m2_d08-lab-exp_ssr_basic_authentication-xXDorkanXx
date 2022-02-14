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

	if(!username || !password) {
        res.render("signup", {errorMessage: "All fields are required"});
        throw new Error("Validation error!");
    };

	User.findOne({username})
	.then(user=>{
		if(user && user.username){
			throw new Error("User already taken!")
		};

		User.create({
            username,
            password:  bcrypt.hashSync(password, bcrypt.genSaltSync(saltRounds))
        })
		.then(()=>{res.render("index", {signupMessage: "You sign up succefully!"})})
		.catch((err)=>{
			console.log(err);
			res.redirect("/auth/signup")})
	})
	.catch((err)=>{
		res.render("signup", {errorMessage: err});
	})
});

router.route("/login")
.get((req, res) => {
  res.render("login");
})
.post((req, res)=>{
	const username = req.body.username;
	let password = req.body.password;

	if (!username || !password) {
        res.render("login", { errorMessage: "All fields are required" });
        throw new Error("Validation error!");
    };

	User.findOne({username})
	.then(user=>{
		if(!user){
			throw new Error("Incorrect credentials!");
		}

		const isPwdCorrect = bcrypt.compareSync(password, user.password);

		if(isPwdCorrect){
			req.session.currentUserId = user._id;
			res.render("index", {signupMessage: "You logged succefully!"});
		}else{
			throw new Error("Incorrect credentials!");
		}
	})
	.catch((err)=>{
		res.render("login", {errorMessage: err});
	})
	
});

router.get("/main", (req, res)=>{
    const id = req.session.currentUserId;
    User.findById(id)
	.then((user)=>{
        if(!user){throw new Error("Validation error!")};
        res.render("main", user);
    })
	.catch((err)=>{
        res.render("index", {errorMessage: err})});
});

router.get("/private", (req, res)=>{
    const id = req.session.currentUserId;
    User.findById(id)
	.then((user)=>{
        if(!user){throw new Error("Validation error!")};
        res.render("private", user);
    })
	.catch((err)=>{
        res.render("index", {errorMessage: err})});
});

router.get("/logout", (req, res)=>{
	req.session.destroy((err)=>{
		res.render("index", {signupMessage: "You logged out succefully!"});
	});
})

module.exports = router;