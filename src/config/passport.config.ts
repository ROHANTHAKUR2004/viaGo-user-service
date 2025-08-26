// config/passport.ts
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import User, { IUser } from "../model/user.model";


// Extend Express User interface
declare global {
  namespace Express {
    interface User extends IUser {}
  }
}

// Social profile interface
interface SocialProfile {
  id: string;
  displayName?: string;
  emails?: Array<{ value: string; verified?: boolean }>;
  photos?: Array<{ value: string }>;
  provider: string;
}

passport.serializeUser((user, done) => {
  done(null, user._id);
});



// Generic social authentication handler
const handleSocialAuth = async (
  profile: SocialProfile,
  done: (error: any, user?: any) => void
) => {
  try {
    const email = profile.emails?.[0]?.value;
    if (!email) {
      return done(new Error("Email is required"));
    }

    // Check if user already has this social provider linked
    let user = await User.findOne({
      "authProvides.provider": profile.provider,
      "authProvides.providerId": profile.id,
    });

    if (user) {
      // Update last login and login count
      user.lastLogin = new Date();
      user.loginCount += 1;
      
      // Update profile data if needed
      const authProvide = user.authProvides.find(
        (ap) => ap.provider === profile.provider && ap.providerId === profile.id
      );
      
      if (authProvide) {
        authProvide.profileData = {
          displayName: profile.displayName,
          avatar: profile.photos?.[0]?.value,
          email: email,
        };
      }
      
      await user.save();
      return done(null, user);
    }

    // Check if user exists with the same email
    user = await User.findOne({ email });

    if (user) {
      // Link social account to existing user
      user.authProvides.push({
        provider: profile.provider,
        providerId: profile.id,
        profileData: {
          displayName: profile.displayName,
          avatar: profile.photos?.[0]?.value,
          email: email,
        },
      });
      
      user.isVerified = true;
      user.lastLogin = new Date();
      user.loginCount += 1;
      
      // Set avatar if not already set
      if (!user.avatar && profile.photos?.[0]?.value) {
        user.avatar = profile.photos[0].value;
      }
      
      await user.save();
      return done(null, user);
    }

    // Create new user
    const username = await generateUniqueUsername(email.split('@')[0]);
    
    const newUser = new User({
      email,
      username,
      authProvides: [{
        provider: profile.provider,
        providerId: profile.id,
        profileData: {
          displayName: profile.displayName,
          avatar: profile.photos?.[0]?.value,
          email: email,
        },
      }],
      avatar: profile.photos?.[0]?.value,
      isVerified: true,
      lastLogin: new Date(),
      loginCount: 1,
    });

    await newUser.save();
    return done(null, newUser);
  } catch (error) {
    return done(error, undefined);
  }
};

// Generate unique username
const generateUniqueUsername = async (base: string): Promise<string> => {
  let username = base;
  let counter = 1;
  
  while (true) {
    const existingUser = await User.findOne({ username });
    if (!existingUser) {
      return username;
    }
    
    username = `${base}${counter}`;
    counter++;
  }
};

// Google Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL!,
        scope: ["profile", "email"],
      },
      async (accessToken, refreshToken, profile, done) => {
        const socialProfile: SocialProfile = {
          id: profile.id,
          displayName: profile.displayName,
          emails: profile.emails,
          photos: profile.photos,
          provider: "google",
        };
        
        await handleSocialAuth(socialProfile, done);
      }
    )
  );
}

export default passport;