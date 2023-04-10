import jwt from 'jsonwebtoken';
import { InvalidArgumentsError } from '@socket-mesh/errors';

export class AuthEngine {
	verifyToken(signedToken: string, key: jwt.Secret | jwt.GetPublicKeyOrSecret, options: jwt.VerifyOptions & { complete: true; }): Promise<string | jwt.JwtPayload> {
		const jwtOptions = Object.assign({}, options || {});

		delete (jwtOptions as any)['socket'];

		if (typeof signedToken === 'string' || signedToken == null) {
			return new Promise((resolve, reject) => {
				jwt.verify(signedToken || '', key, jwtOptions, (err, token) => {
					if (err) {
						reject(err);
						return;
					}
					resolve(token);
				});
			});
		}

		return Promise.reject(
			new InvalidArgumentsError('Invalid token format - Token must be a string')
		);
	}

	signToken(token: string | object | Buffer, key: jwt.Secret, options: jwt.SignOptions): Promise<string | undefined> {
		const jwtOptions = Object.assign({}, options || {});

		return new Promise<string | undefined>((resolve, reject) => {
			jwt.sign(token, key, jwtOptions, (err, signedToken) => {
				if (err) {
					reject(err);
					return;
				}
				resolve(signedToken);
			});
		});
	}
}