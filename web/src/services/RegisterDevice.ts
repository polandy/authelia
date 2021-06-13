import {
    InitiateTOTPRegistrationPath,
    CompleteTOTPRegistrationPath,
    InitiateU2FRegistrationPath,
    CompleteU2FRegistrationStep1Path,
    CompleteU2FRegistrationStep2Path,
} from "./Api";
import { Post, PostWithOptionalResponse } from "./Client";

export async function initiateTOTPRegistrationProcess() {
    await PostWithOptionalResponse(InitiateTOTPRegistrationPath);
}

interface CompleteTOTPRegistrationResponse {
    base32_secret: string;
    otpauth_url: string;
}

export async function completeTOTPRegistrationProcess(processToken: string) {
    return Post<CompleteTOTPRegistrationResponse>(CompleteTOTPRegistrationPath, { token: processToken });
}

export async function initiateU2FRegistrationProcess() {
    return PostWithOptionalResponse(InitiateU2FRegistrationPath);
}

export async function completeU2FRegistrationProcessStep1(processToken: string) {
    return Post<CredentialCreationOptions>(CompleteU2FRegistrationStep1Path, { token: processToken });
}

export async function completeU2FRegistrationProcessStep2(response: Credential) {
    return PostWithOptionalResponse(CompleteU2FRegistrationStep2Path, response);
}
