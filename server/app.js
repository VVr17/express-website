const express = require('express');
const compression = require('compression') // compress app to send it to browser
const helmet = require('helmet'); // secure Express apps by setting HTTP response headers

// dependencies to create session and store it in Mongo
const cookieParser = require('cookie-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo')(session);

const path = require('path');
const createError = require('http-errors');
const bodyParser = require('body-parser');
const routes = require('./routes');
const auth = require('./lib/auth'); // Passport dependencies

// Services
const SpeakerService = require('./services/SpeakerService');
const FeedbackService = require('./services/FeedbackService');
const AvatarService = require('./services/AvatarService');

module.exports = (config) => {
  const app = express();
  app.use(helmet());
  app.use(compression());
  const speakers = new SpeakerService(config.data.speakers);
  const feedback = new FeedbackService(config.data.feedback);
  const avatars = new AvatarService(config.data.avatars);

  app.set('view engine', 'pug');
  app.set('views', path.join(__dirname, './views'));

  app.locals.title = config.sitename;

  app.use('/', express.static(path.join(__dirname, '../public')));
  app.get('/favicon.ico', (req, res) => res.sendStatus(204));

  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(cookieParser());

  if(app.get('env') === 'production'){
    app.set('trust proxy', 'loopback');
    app.use(session({
      secret: 'very secret 12345',
      name: 'sessionId',
      proxy: true,
      // cookie: {secure: true},
      resave: true,
      saveUninitialized: false,
      store: new MongoStore({ mongooseConnection: mongoose.connection }),
    }));
  }else{
    app.use(session({
      secret: 'very secret 12345',
      resave: true,
      saveUninitialized: false,
      store: new MongoStore({ mongooseConnection: mongoose.connection }),
    }));
  }

  app.use(auth.initialize);  // passport.initialize()
  app.use(auth.session); //  passport.session()
  app.use(auth.setUser); // set user to req.user

  app.use(async (req, res, next) => {
    try {
      const names = await speakers.getNames();
      res.locals.speakerNames = names;
      return next();
    } catch (err) {
      return next(err);
    }
  });

  app.use('/', routes({ speakers, feedback, avatars }));

  // catch 404 and forward to error handler
  app.use((req, res, next) => {
    next(createError(404));
  });

  if (app.get('env') === 'development') {
    app.locals.pretty = true;
  }

  // error handler
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res.locals.message = err.message;
    const status = err.status || 500; // If no status is provided, let's assume it's a 500
    res.locals.status = status;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
    res.status(status);
    res.render('error');
  });

  return app;
};
