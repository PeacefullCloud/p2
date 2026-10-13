<script setup>
import { computed, reactive, ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Button, FormControl, toast, FeatherIcon } from 'frappe-ui'
import { useLogin, useMfaVerify } from '../stores/auth'
import { saveTokens, decodeUserFromToken } from '../stores/api'

const router = useRouter()
const { login, loading, error: loginError } = useLogin()
const { verify: verifyMfa, loading: verifyingMfa } = useMfaVerify()
const form = reactive({ username: '', password: '' })
const error = reactive({ message: '' })

// Second step: shown only when /auth/login reports the account has TOTP
// 2FA enabled. mfaToken binds this code entry to the just-verified password.
const mfaStep = ref(false)
const mfaToken = ref('')
const mfaCode = ref('')

// Providers actually configured by an admin (SocialApp rows), fetched from
// the server so users never see a dead SSO button for an unconfigured
// provider. Presentation metadata for known providers is merged in below.
const providerMeta = {
  google: { label: 'Google', icon: 'chrome' },
  microsoft: { label: 'Microsoft', icon: 'square' },
  github: { label: 'GitHub', icon: 'github' },
}
const configuredProviders = ref([])
const ssoProviders = computed(() =>
  configuredProviders.value.map((p) => ({
    id: p.id,
    // The admin-configured Display Name (Settings > SSO Providers) is the
    // button text; the built-in label is only a fallback.
    label: p.name?.trim() || providerMeta[p.id]?.label || p.id,
    icon: providerMeta[p.id]?.icon || 'key',
    loginUrl: p.login_url || `/_/accounts/${p.id}/login/`,
  })),
)

async function fetchConfiguredProviders() {
  try {
    const resp = await fetch('/api/v1/system/sso-providers/public/')
    if (resp.ok) configuredProviders.value = await resp.json()
  } catch {
    configuredProviders.value = []
  }
}

function loginWithProvider(provider) {
  // Full page navigation is required here (not a fetch/XHR) — the browser
  // must actually visit the provider's consent screen and come back.
  window.location.href = provider.loginUrl
}

// Step 3: Forced 2FA enrollment (required by organization auth policy)
const enrollmentStep = ref(false)
const enrollmentToken = ref('')
const enrollmentData = ref(null) // { secret, otpauth_url, qr_svg }
const enrollmentCode = ref('')
const recoveryCodes = ref(null)
const enrolling = ref(false)

async function startForcedEnrollment(token) {
  enrollmentToken.value = token
  enrollmentCode.value = ''
  recoveryCodes.value = null
  enrolling.value = true
  error.message = ''
  try {
    const resp = await fetch('/api/v1/auth/mfa/enroll-setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enrollment_token: token }),
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || 'Failed to start 2FA setup')
    }
    enrollmentData.value = await resp.json()
    enrollmentStep.value = true
    mfaStep.value = false
  } catch (e) {
    error.message = e.message
  } finally {
    enrolling.value = false
  }
}

async function handleEnrollConfirm() {
  if (!enrollmentCode.value.trim()) return
  enrolling.value = true
  error.message = ''
  try {
    const resp = await fetch('/api/v1/auth/mfa/enroll-confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollment_token: enrollmentToken.value,
        code: enrollmentCode.value.trim(),
      }),
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || 'Incorrect code')
    }
    const data = await resp.json()
    recoveryCodes.value = data.recovery_codes
    saveTokens(data.access, data.refresh)
    decodeUserFromToken(data.access)
  } catch (e) {
    error.message = e.message
  } finally {
    enrolling.value = false
  }
}

function finishEnrollment() {
  toast.success('Two-factor authentication enabled!')
  router.push({ name: 'Dashboard' })
}

function cancelEnrollment() {
  enrollmentStep.value = false
  enrollmentToken.value = ''
  enrollmentData.value = null
  enrollmentCode.value = ''
  recoveryCodes.value = null
  error.message = ''
}

// After a successful SSO round trip the server redirects back to
// /login?sso_code=... — an opaque single-use code, never a token. Exchange it
// over POST, then continue the same way as password auth.
// Reason codes sent by the server in /login?sso_error=<code>.
const SSO_ERRORS = {
  no_account: 'No account exists for this email. Ask your administrator to add you, then try again.',
  email_unverified: 'Your provider did not confirm your email address, so we cannot sign you in with it.',
  domain_not_allowed: 'Your email domain is not allowed to sign in here.',
  ambiguous_account: 'More than one account uses this email. Contact your administrator.',
  account_disabled: 'This account is disabled. Contact your administrator.',
  cancelled: 'Sign-in was cancelled.',
  provider_error: 'The sign-in provider returned an error. Please try again.',
  policy_check_failed: 'Sign-in could not be completed. Please try again.',
  login_failed: 'Sign-in could not be completed. Please try again.',
  default: 'SSO sign-in failed. Please try again or contact an administrator.',
}

// Forced password change (default admin/admin, or any flagged account).
const passwordStep = ref(false)
const passwordChangeToken = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const changingPassword = ref(false)

// Route a server login response to whichever step comes next.
async function continueAfterAuth(data, replace = false) {
  if (data.password_change_required && data.password_change_token) {
    passwordChangeToken.value = data.password_change_token
    newPassword.value = ''
    confirmPassword.value = ''
    mfaStep.value = false
    passwordStep.value = true
    return
  }
  passwordStep.value = false
  if (data.mfa_setup_required && data.enrollment_token) {
    await startForcedEnrollment(data.enrollment_token)
    return
  }
  if (data.mfa_required && data.mfa_token) {
    mfaToken.value = data.mfa_token
    mfaStep.value = true
    return
  }
  saveTokens(data.access, data.refresh)
  decodeUserFromToken(data.access)
  toast.success('Welcome back!')
  const target = { name: 'Dashboard' }
  if (replace) router.replace(target)
  else router.push(target)
}

async function handlePasswordChange() {
  error.message = ''
  if (newPassword.value !== confirmPassword.value) {
    error.message = 'The two passwords do not match.'
    return
  }
  changingPassword.value = true
  try {
    const resp = await fetch('/api/v1/auth/password-change', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        password_change_token: passwordChangeToken.value,
        new_password: newPassword.value,
      }),
    })
    const data = await resp.json().catch(() => ({}))
    if (!resp.ok) {
      if (resp.status === 401 || resp.status === 429) cancelPasswordChange()
      throw new Error(data.detail || 'Could not change the password.')
    }
    form.password = ''
    await continueAfterAuth(data)
  } catch (e) {
    error.message = e.message
  } finally {
    changingPassword.value = false
  }
}

function cancelPasswordChange() {
  passwordStep.value = false
  passwordChangeToken.value = ''
  newPassword.value = ''
  confirmPassword.value = ''
}

async function exchangeSsoCode(code) {
  try {
    const resp = await fetch('/api/v1/auth/sso/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    })
    const data = await resp.json().catch(() => ({}))
    if (!resp.ok) throw new Error(data.detail || 'SSO sign-in failed. Please try again.')
    await continueAfterAuth(data, true)
  } catch (e) {
    error.message = e.message
  }
}

onMounted(() => {
  fetchConfiguredProviders()

  const params = new URLSearchParams(window.location.search)
  const ssoCode = params.get('sso_code')
  const ssoError = params.get('sso_error')

  if (ssoCode || ssoError) {
    // Drop the one-time code from the address bar and history right away.
    window.history.replaceState({}, '', window.location.pathname)
  }
  if (ssoError) {
    error.message = SSO_ERRORS[ssoError] || SSO_ERRORS.default
    return
  }
  if (ssoCode) exchangeSsoCode(ssoCode)
})

async function handleLogin() {
  error.message = ''
  try {
    const result = await login(form.username, form.password)
    if (result.passwordChangeRequired) {
      await continueAfterAuth({
        password_change_required: true,
        password_change_token: result.passwordChangeToken,
      })
      return
    }
    if (result.mfaRequired) {
      mfaToken.value = result.mfaToken
      mfaStep.value = true
      return
    }
    if (result.mfaSetupRequired) {
      await startForcedEnrollment(result.enrollmentToken)
      return
    }
    toast.success('Welcome back!')
    router.push({ name: 'Dashboard' })
  } catch (e) {
    error.message = e.message
  }
}

async function handleMfaVerify() {
  error.message = ''
  try {
    await verifyMfa(mfaToken.value, mfaCode.value)
    toast.success('Welcome back!')
    router.push({ name: 'Dashboard' })
  } catch (e) {
    // The challenge is gone (expired, used, or too many wrong guesses) —
    // retrying with the same token can never succeed, so send the user
    // back to the password step for a fresh challenge instead of letting
    // them burn attempts on a dead token.
    if (/expired|already used|too many|log in again/i.test(e.message || '')) {
      cancelMfa()
      error.message = 'That verification session expired. Please sign in again.'
      return
    }
    error.message = e.message
  }
}

function cancelMfa() {
  mfaStep.value = false
  mfaToken.value = ''
  mfaCode.value = ''
  error.message = ''
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-surface-gray-1 px-4">
    <div class="w-full max-w-sm">
      <!-- Logo / branding -->
      <div class="mb-8 text-center">
        <div class="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-surface-white border border-outline-gray-1 shadow-sm">
          <FeatherIcon name="hard-drive" class="h-7 w-7 text-ink-gray-7" />
        </div>
        <h1 class="text-2xl font-semibold text-ink-gray-9">P2 Storage Manager</h1>
        <p class="mt-1 text-p-sm text-ink-gray-5">Sign in to manage your object storage</p>
      </div>

      <!-- Recovery Codes Display (after successful forced enrollment) -->
      <div
        v-if="recoveryCodes"
        class="space-y-4 rounded-lg border border-outline-gray-1 bg-surface-white p-6 shadow-sm"
      >
        <div class="text-center">
          <FeatherIcon name="key" class="mx-auto mb-2 h-6 w-6 text-green-600" />
          <p class="text-p-base font-medium text-ink-gray-9">Save Your Recovery Codes</p>
          <p class="mt-1 text-p-xs text-ink-gray-5">
            Store these codes in a secure location. Each code can be used once if you lose access to your authenticator app.
          </p>
        </div>

        <div class="grid grid-cols-2 gap-2 rounded-md bg-surface-gray-2 p-3 font-mono text-xs text-ink-gray-9 text-center">
          <span v-for="rc in recoveryCodes" :key="rc" class="bg-surface-white py-1 px-2 rounded border border-outline-gray-1">
            {{ rc }}
          </span>
        </div>

        <Button
          variant="solid"
          theme="gray"
          label="Continue to Dashboard"
          class="w-full"
          @click="finishEnrollment"
        />
      </div>

      <!-- Forced password change (default or flagged credentials) -->
      <form
        v-else-if="passwordStep"
        class="space-y-4 rounded-lg border border-outline-gray-1 bg-surface-white p-6 shadow-sm"
        @submit.prevent="handlePasswordChange"
      >
        <div class="text-center">
          <FeatherIcon name="lock" class="mx-auto mb-2 h-6 w-6 text-amber-600" />
          <p class="text-p-base font-medium text-ink-gray-9">Set a new password</p>
          <p class="mt-1 text-p-sm text-ink-gray-5">
            This account is still using a default password. Choose a new one to continue.
          </p>
        </div>
        <FormControl
          v-model="newPassword"
          type="password"
          label="New password"
          autocomplete="new-password"
          required
        />
        <FormControl
          v-model="confirmPassword"
          type="password"
          label="Confirm new password"
          autocomplete="new-password"
          required
        />

        <p v-if="error.message" class="text-p-sm text-ink-red-6">{{ error.message }}</p>

        <Button
          variant="solid"
          theme="gray"
          type="submit"
          :loading="changingPassword"
          label="Change password & continue"
          class="w-full"
        />
        <Button variant="ghost" theme="gray" class="w-full" label="Cancel" @click="cancelPasswordChange" />
      </form>

      <!-- Step 3: Forced TOTP Enrollment (required by policy) -->
      <div
        v-else-if="enrollmentStep"
        class="space-y-4 rounded-lg border border-outline-gray-1 bg-surface-white p-6 shadow-sm"
      >
        <div class="text-center">
          <FeatherIcon name="shield" class="mx-auto mb-2 h-6 w-6 text-blue-600" />
          <p class="text-p-base font-medium text-ink-gray-9">2FA Setup Required</p>
          <p class="mt-1 text-p-xs text-ink-gray-5">
            Your organization requires two-factor authentication. Scan this QR code with an authenticator app.
          </p>
        </div>

        <div v-if="enrollmentData" class="flex flex-col items-center gap-2">
          <div
            v-html="enrollmentData.qr_svg"
            class="h-44 w-44 rounded-md border border-outline-gray-1 bg-white p-2 flex items-center justify-center [&>svg]:h-full [&>svg]:w-full"
          />
          <div class="text-center w-full">
            <p class="text-p-xs text-ink-gray-4">Manual entry code:</p>
            <code class="text-xs font-mono text-ink-gray-8 bg-surface-gray-2 px-2 py-0.5 rounded break-all select-all">
              {{ enrollmentData.secret }}
            </code>
          </div>
        </div>

        <div v-else class="py-8 text-center text-sm text-ink-gray-5">
          Generating 2FA key...
        </div>

        <form @submit.prevent="handleEnrollConfirm" class="space-y-4">
          <FormControl
            v-model="enrollmentCode"
            label="Verification code"
            type="text"
            placeholder="6-digit code"
            autocomplete="one-time-code"
            required
          />

          <p v-if="error.message" class="text-p-sm text-ink-red-6">{{ error.message }}</p>

          <Button
            variant="solid"
            theme="gray"
            type="submit"
            :loading="enrolling"
            label="Verify & Complete Setup"
            class="w-full"
          />
          <Button variant="ghost" theme="gray" class="w-full" label="Cancel" @click="cancelEnrollment" />
        </form>
      </div>

      <!-- Step 2: TOTP / recovery code (only shown after password auth
           reports the account has 2FA enabled) -->
      <form
        v-else-if="mfaStep"
        class="space-y-4 rounded-lg border border-outline-gray-1 bg-surface-white p-6 shadow-sm"
        @submit.prevent="handleMfaVerify"
      >
        <div class="text-center">
          <FeatherIcon name="shield" class="mx-auto mb-2 h-6 w-6 text-ink-gray-7" />
          <p class="text-p-base font-medium text-ink-gray-9">Two-factor authentication</p>
          <p class="mt-1 text-p-sm text-ink-gray-5">
            Enter the 6-digit code from your authenticator app, or a recovery code.
          </p>
        </div>
        <FormControl
          v-model="mfaCode"
          label="Authentication code"
          type="text"
          placeholder="123456"
          autocomplete="one-time-code"
          required
        />

        <p v-if="error.message" class="text-p-sm text-ink-red-6">{{ error.message }}</p>

        <Button
          variant="solid"
          theme="gray"
          type="submit"
          :loading="verifyingMfa"
          label="Verify"
          class="w-full"
        />
        <Button variant="ghost" theme="gray" class="w-full" label="Back" @click="cancelMfa" />
      </form>

      <!-- Step 1: username + password -->
      <form
        v-else
        class="space-y-4 rounded-lg border border-outline-gray-1 bg-surface-white p-6 shadow-sm"
        @submit.prevent="handleLogin"
      >
        <FormControl
          v-model="form.username"
          label="Username"
          type="text"
          placeholder="Enter your username"
          required
        />
        <FormControl
          v-model="form.password"
          type="password"
          label="Password"
          placeholder="Enter your password"
          required
        />

        <p v-if="error.message" class="text-p-sm text-ink-red-6">{{ error.message }}</p>

        <Button
          variant="solid"
          theme="gray"
          type="submit"
          :loading="loading"
          label="Sign In"
          class="w-full"
        />
      </form>

      <div v-if="!mfaStep && !passwordStep && !enrollmentStep && !recoveryCodes && ssoProviders.length" class="mt-4 space-y-2">
        <div class="flex items-center gap-2">
          <div class="h-px flex-1 bg-outline-gray-2" />
          <span class="text-p-xs text-ink-gray-5">or continue with</span>
          <div class="h-px flex-1 bg-outline-gray-2" />
        </div>
        <Button
          v-for="provider in ssoProviders"
          :key="provider.id"
          variant="outline"
          theme="gray"
          class="w-full"
          @click="loginWithProvider(provider)"
        >
          <template #prefix>
            <FeatherIcon :name="provider.icon" class="h-4 w-4" />
          </template>
          {{ provider.label }}
        </Button>
      </div>

      <p class="mt-4 text-center text-p-xs text-ink-gray-5">
        p2 Storage Engine
      </p>
    </div>
  </div>
</template>
