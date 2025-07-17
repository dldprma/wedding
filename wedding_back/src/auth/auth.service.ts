import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
  constructor(private userService: UsersService) {}

  async register(email: string, password: string) {
    const existing = await this.userService.findByEmail(email);
    if (existing) throw new Error('이미 가입된 이메일입니다.');
    const hashed = await bcrypt.hash(password, 10);
    const user = await this.userService.create({ email, password: hashed });
    return { id: user.id, email: user.email };
  }

  async login(email: string, password: string) {
    const user = await this.userService.findByEmail(email);
    if (!user)
      throw new UnauthorizedException(
        '이메일 or 비밀번호가 올바르지 않습니다.',
      );
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      throw new UnauthorizedException(
        '이메일 or 비밀번호가 올바르지 않습니다.',
      );

    // JWT 토큰 발급
    const token = jwt.sign({ sub: user.id, email: user.email }, 'SECRET_KEY', {
      expiresIn: '1h',
    });
    return { access_token: token };
  }
}
