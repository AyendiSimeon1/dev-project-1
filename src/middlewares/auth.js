const bcrypt = require('bcryptjs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const FacebookStrategy =  require('passport-facebook').Strategy;
const { PrismaClient } = require('@prisma/client');
const dotenv = require('dotenv');
const { generateUniqueEmail } = require('./generateUniqueEmail');

dotenv.config();

const prisma = new PrismaClient({
  log: ['error'],
});

const saltRounds = 10;

// Hash a password
async function hashPassword(password) {
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  } catch (error) {
    console.error('Error hashing password:', error);
    throw new Error(`Internal server error from hashing password: ${error}`);
  }
}

// Compare a password with a hash
async function comparePassword(password, hash) {
  try {
    const match = await bcrypt.compare(password, hash);
    return match;
  } catch (error) {
    console.error('Error comparing passwords:', error);
    throw new Error(`Internal server error from comparing passwords: ${error}`);
  }
}

// Passport Config
passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
    passReqToCallback: true,
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      const existingUser = await prisma.User.findUnique({
        where: { email: profile.emails[0].value },
      });
      if (existingUser) {
        console.log('User already exists');
        return done(null, existingUser);
      }
      const newUser = await prisma.User.create({
        data: {
          username: profile.name.givenName,
          email: profile.emails[0].value,
          password: '',
        },
      });
      return done(null, newUser);
    } catch (error) {
      console.error('Error creating user:', error);
      return done(error);
    }
  },
));


passport.use(new FacebookStrategy(
  {
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: '/auth/facebook/callback',
    passReqToCallback: true,
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      const facebookId = profile.id; 
      const userId = parseInt(facebookId); 
      
      const username = profile.username;

      const existingUser = await prisma.User.findUnique({
        where: { id: userId },
      });
     
      if(existingUser) {
        console.log('User already exists');
        return done(null, existingUser);
      } 

      const uniqueEmail = generateUniqueEmail('user');

      const newUser = await prisma.User.create({
        data: {
          id: profile.id[0].value,
          email:  uniqueEmail,
          password: '', 
          username:  profile.username,
        }           
      });

      return done(null, newUser);
    } catch (error) {
      if (error.code === 'P2002' && error.meta?.target?.includes('email')) {
        console.error('Email already exists:', error);
      } else {
        console.error('Error creating user:', error);
      }
    }
}));


// Passport Serializer
const customSerialize = (sessionData) => {
  const serializedData = { ...sessionData };
  if (serializedData.id) {
    serializedData.id = serializedData.id.toString();
  }
  return JSON.stringify(serializedData);
};


const customDeserialize = (serializedData) => {
  const sessionData = JSON.parse(serializedData);
  // Convert strings back to BigInt values
  if (sessionData.id) {
    sessionData.id = BigInt(sessionData.id);
  }

  return sessionData;
};

passport.serializeUser((user, done) => {
  const serializedUser = customSerialize(user);
  done(null, serializedUser);
});

passport.deserializeUser((serializedUser, done) => {
  const user = customDeserialize(serializedUser);
  done(null, user);
});

module.exports = { hashPassword, comparePassword, passport };
