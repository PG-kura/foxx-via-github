'use strict';
const db = require('@arangodb').db;
const joi = require('joi');
const createAuth = require('@arangodb/foxx/auth');
const createRouter = require('@arangodb/foxx/router');
const sessionsMiddleware = require('@arangodb/foxx/sessions');

const auth = createAuth();
const router = createRouter();
const users_colname = module.context.collectionName('Users');
const sessions_colname = module.context.collectionName('Sessions');

if (!db._collection(users_colname)) {
  db._createDocumentCollection(users_colname);
}
db._collection(users_colname).ensureIndex({
  type: 'hash',
  fields: ['username'],
  unique: true
});

if(!db._collection(sessions_colname)) {
  db._createDocumentCollection(sessions_colname);
}
const sessions = sessionsMiddleware({
  storage: module.context.collection('Sessions'),
  transport: ['header', 'cookie']
});

module.context.use(sessions);
module.context.use(router);

router.get('/whoami', function (req, res) {
  try {
    const user = db._collection(users_colname).document(req.session.uid);
    res.send({username: user.username});
  } catch (e) {
    res.send({username: null});
  }
})
.description('Returns the currently active username.');

router.post('/login', function (req, res) {
  // This may return a user object or null
  const user = db._collection(users_colname).firstExample({
    username: req.body.username
  });
  const valid = auth.verify(
    // Pretend to validate even if no user was found
    user ? user.authData : {},
    req.body.password
  );
  if (!valid) res.throw('unauthorized');
  
  // Log the user in
  
  req.session.uid = user._key;
  req.sessionStorage.save(req.session);
  res.send({sucess: true});
})
.body(joi.object({
  username: joi.string().required(),
  password: joi.string().required()
}).required(), 'Credentials')
.description('Logs a registered user in.');

router.post('/logout', function (req, res) {
  if (req.session.uid) {
    req.session.uid = null;
    req.sessionStorage.save(req.session);
  }
  res.send({success: true});
})
.description('Logs the current user out.');

router.post('/signup', function (req, res) {
  const user = req.body;
  try {
    // Create an authentication hash
    user.authData = auth.create(user.password);
    delete user.password;
    console.log(user);
    const meta = db._collection(users).save(user);
    Object.assign(user, meta);
  } catch (e) {
    // Failed to save the user
    // We'll assume the UniqueConstraint has been violated
    res.throw('bad request', 'Username already taken', e);
  }
  // Log the user in
  req.session.uid = user._key;
  req.sessionStorage.save(req.session);
  res.send({success: true});
})
.body(joi.object({
  username: joi.string().required(),
  password: joi.string().required()
}).required(), 'Credentials')
.description('Creates a new user and logs them in.');
