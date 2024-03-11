const bcrypt = require('bcryptjs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const { PrismaClient } = require('@prisma/client');
const dotenv = require('dotenv');

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

// Passport Serializer
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (error) {
    done(error);
  }
});

module.exports = { hashPassword, comparePassword, passport };
