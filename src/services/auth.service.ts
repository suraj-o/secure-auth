import argon2 from 'argon2';
import { User } from '../models/User';
import { issueNewTokens } from './token.service';

export async function register(email: string, password: string, ip?: string, userAgent?: string) {
  const existing = await User.findOne({ email });
  if (existing) throw new Error('Email already registered');
  const passwordHash = await argon2.hash(password);
  const user = await User.create({ email, passwordHash, refreshTokens: [] });
  const { access, refresh, cookie } = await issueNewTokens(user.id, undefined, ip, userAgent);
  return { user, access, refresh, cookie };
}

export async function login(email: string, password: string, ip?: string, userAgent?: string) {
  const user = await User.findOne({ email });
  if (!user) throw new Error('Invalid credentials');
  const ok = await argon2.verify(user.passwordHash, password);
  if (!ok) throw new Error('Invalid credentials');
  const { access, refresh, cookie } = await issueNewTokens(user.id, undefined, ip, userAgent);
  return { user, access, refresh, cookie };
}
