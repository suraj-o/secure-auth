import { Schema, model, Document } from 'mongoose';

export interface RefreshRecord {
  jti: string;
  familyId: string;
  hashedToken: string;
  createdAt: Date;
  expiresAt: Date;
  revokedAt?: Date;
  replacedBy?: string;
  ip?: string;
  userAgent?: string;
}

export interface IUser extends Document {
  email: string;
  passwordHash: string;
  refreshTokens: RefreshRecord[];
}

const RefreshSchema = new Schema<RefreshRecord>({
  jti: { 
    type: String, 
    required: true 
  },
  familyId: { 
    type: String, 
    required: true 
  },
  hashedToken: { 
    type: String, 
    required: true 
  },
  createdAt: { 
    type: Date, 
    required: true 
  },
  expiresAt: { 
    type: Date, 
    required: true 
  },
  revokedAt: { 
    type: Date 
  },
  replacedBy: { 
    type: String 
  },
  ip: String,
  userAgent: String
}, 
{ 
  _id: false 
}
);

const UserSchema = new Schema<IUser>({
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    index: true 
  },
  passwordHash: { 
    type: String, 
    required: true 
  },
  refreshTokens: { 
    type: [RefreshSchema], 
    default: [] 
  }
}, { timestamps: true });

export const User = model<IUser>('User', UserSchema);
