import { AuthEngine } from "../src";
import { InvalidArgumentsError } from '@socket-mesh/errors';
import jwt from 'jsonwebtoken';

describe('AuthEngine', () => {
  const authEngine = new AuthEngine();

  describe('verifyToken', () => {
    it('should return a Promise<string | JwtPayload>', async () => {
      const signedToken = jwt.sign({ sub: '123' }, 'secret');
      const result = await authEngine.verifyToken(signedToken, 'secret', { complete: true });
      expect(result).toEqual(expect.any(Object));
    });

    it('should throw an InvalidArgumentsError when signedToken is not a string', async () => {
      const result = authEngine.verifyToken(123 as any, 'secret', { complete: true });
      await expect(result).rejects.toThrow(InvalidArgumentsError);
    });
  });

  describe('signToken', () => {
    it('should return a Promise<string | undefined>', async () => {
      const token = { sub: '123' };
      const result = await authEngine.signToken(token, 'secret', { expiresIn: '1h' });
      expect(result).toEqual(expect.any(String));
    });
  });
});
