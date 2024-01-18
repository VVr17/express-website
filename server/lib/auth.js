const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const UserModel = require('../models/UserModel');

passport.use(new LocalStrategy({ usernameField: 'email' }, async (username, password, done) => {
  try {
    const user = await UserModel.findOne({ email: username }).exec();
    if (!user) {
      return done(null, false, { message: 'Invalid username or password' });
    }
    const passwordOK = await user.comparePassword(password); // using bcrypt compare
    if (!passwordOK) {
      return done(null, false, { message: 'Invalid username or password' });
    }
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Template for GoogleStrategy - actual credentials need to be added 
passport.use(new GoogleStrategy({
  clientID: 'google-client-id',
  clientSecret: 'google-client-secret',
  callbackURL: 'http://app/callback/google', // Update this with actual callback URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Find or create a user based on the Google profile information
    const user = await UserModel.findOneAndUpdate(
      { googleId: profile.id },
      {
        $setOnInsert: {
          googleId: profile.id,
          email: profile.emails[0].value,
          // Other user properties from the Google profile
        },
      },
      { upsert: true, new: true }
    ).exec();

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));


// eslint-disable-next-line no-underscore-dangle
passport.serializeUser((user, done) => done(null, user._id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await UserModel.findById(id).exec();
    return done(null, user);
  } catch (err) {
    return done(err);
  }
});

module.exports = {
  initialize: passport.initialize(),
  session: passport.session(),
  setUser: (req, res, next) => {
    res.locals.user = req.user;
    return next();
  },
};
