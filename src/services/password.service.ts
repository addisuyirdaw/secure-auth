import bcrypt from 'bcrypt';
import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';
import { env } from '../config/env';

const zxcvbn = new ZxcvbnFactory({
  dictionary: {
    ...zxcvbnCommonPackage.dictionary,
    ...zxcvbnEnPackage.dictionary,
  },
  graphs: zxcvbnCommonPackage.adjacencyGraphs,
  translations: zxcvbnEnPackage.translations,
});

export class PasswordService {
  static async hash(password: string): Promise<string> {
    return bcrypt.hash(password, parseInt(env.BCRYPT_ROUNDS, 10));
  }

  static async verify(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  static validateStrength(password: string): { valid: boolean; score: number; feedback: string[] } {
    // Minimum length gate before zxcvbn analysis
    if (password.length < 12) {
      return { valid: false, score: 0, feedback: ['Password must be at least 12 characters'] };
    }

    const result = zxcvbn.check(password);
    const minScore = 3; // 0-4 scale; 3 = "good"

    const feedback = result.feedback.suggestions.length > 0
      ? result.feedback.suggestions
      : result.feedback.warning ? [result.feedback.warning] : [];

    return {
      valid: result.score >= minScore,
      score: result.score,
      feedback,
    };
  }
}