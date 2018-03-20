const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');


// Create local strategy
const localOptions = {
    usernameField: 'email'
};

const localLogin = new LocalStrategy(localOptions, function(email, password, done){
    // Verify this email and password, cal done with the user
    // if it is the correct email and password
    // otherwise, call done with false
    User.findOne({ email: email}, function(err, user) {
        if (err) { return done(err);}
        if(!user) { return done(null, false);}

        // Compare passwords - is 'password' equal to user.password?
        user.comparePassword(password, function(err, isMatch) {
            //Error occureced
            if(err) { return done(err);}

            // Password did not match user
            if(!isMatch) { return done(null, false);}

            // User authenticated
            return done(null, user);
        })

    })

});


// Setup options for JWT JwtStrategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
}

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
    // See if the user ID in the payload exists in our database
    // If it does, call 'done' with that other
    // otherwise, call done without a user object

    User.findById(payload.sub, function(err, user)  {
        if(err) {return done(err, false);}

        if(user) {
            // done function defined in passport
            // Done without an error
            // and pass in the user
            done(null, user);
        } else {
            // Done without an error
            // no user
            done(null, false);
        }

    });
});

//Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
