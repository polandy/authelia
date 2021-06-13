import { InitiateU2FSignInPath, CompleteU2FSignInPath } from "./Api";
import { Post, PostWithOptionalResponse } from "./Client";
import { SignInResponse } from "./SignIn";

export async function initiateU2FSignin() {
    return Post<CredentialRequestOptions>(InitiateU2FSignInPath);
}

interface CompleteWebAuthnSigninBody extends Credential {
    targetURL?: string;
}

export function completeU2FSignin(credential: Credential, targetURL: string | undefined) {
    const body: CompleteWebAuthnSigninBody = credential;
    if (targetURL) {
        body.targetURL = targetURL;
    }
    return PostWithOptionalResponse<SignInResponse>(CompleteU2FSignInPath, body);
}
