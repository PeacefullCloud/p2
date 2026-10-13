<script setup>
import { ref, watch, computed } from 'vue'
import { Button, Dialog, Badge, TabButtons, FormControl, toast, FeatherIcon, confirmDialog } from 'frappe-ui'
import { useSettingsSingleton } from '../stores/settings'
import { isSuperAdmin } from '../stores/auth'

const {
  config, configLoading,
  apiKeys, keysLoading, createApiKey, keyCreating, deleteApiKey,
  users, usersLoading, createUser, userCreating, updateUser, deleteUser,
  policies, policiesLoading, createPolicy, updatePolicy, deletePolicy,
  mfaEnabled, mfaStatusLoading, setupMfa, mfaSettingUp, confirmMfa, mfaConfirming, disableMfa, mfaDisabling, changeOwnPassword,
  authPolicies, authPoliciesLoading, fetchAuthPolicies, createAuthPolicy, updateAuthPolicy, deleteAuthPolicy, getAffectedCount,
  groups, groupsLoading, fetchGroups,
  ssoProviders, ssoProvidersLoading, fetchSsoProviders, availableProviders, createSsoProvider, updateSsoProvider, deleteSsoProvider,
  ssoSettings, fetchSsoSettings, saveSsoSettings,
} = useSettingsSingleton()

const activeTab = ref('keys')

const tabs = computed(() => {
  const items = [
    { label: 'API Keys', value: 'keys', icon: 'key' },
  ]
  if (isSuperAdmin.value) {
    items.push({ label: 'Users', value: 'users', icon: 'users' })
  }
  items.push({ label: 'Security', value: 'security', icon: 'lock' })
  if (isSuperAdmin.value) {
    items.push(
      { label: 'Login Policy', value: 'login-policy', icon: 'shield' },
      { label: 'SSO Providers', value: 'sso-providers', icon: 'globe' },
      { label: 'Serve Rules', value: 'policies', icon: 'layers' },
    )
  }
  items.push({ label: 'System', value: 'config', icon: 'settings' })
  return items
})

watch(isSuperAdmin, (val) => {
  if (!val && ['users', 'login-policy', 'sso-providers', 'policies'].includes(activeTab.value)) {
    activeTab.value = 'keys'
  }
}, { immediate: true })

// ── API Key create dialog ──────────────────────────────────────────────────
const showKeyDialog = ref(false)
const keyFormName = ref('')
const newSecret = ref('')

watch(showKeyDialog, (val) => {
  if (val) { keyFormName.value = ''; newSecret.value = '' }
})

async function handleCreateKey(close) {
  try {
    const data = await createApiKey({ name: keyFormName.value })
    newSecret.value = data.secret_key
    toast.success(`API Key "${data.name}" created`)
    keyFormName.value = ''
    close()
  } catch (e) {
    toast.error(e.message)
  }
}

function promptDeleteKey(key) {
  confirmDialog({
    title: 'Delete API Key?',
    message: `Access key "${key.access_key}" will stop working immediately.`,
    theme: 'red',
    confirmLabel: 'Delete',
    onConfirm: async ({ hideDialog }) => {
      await deleteApiKey(key.id)
      toast.success(`API Key "${key.name}" deleted`)
      hideDialog()
    },
  })
}

// ── Policy create/edit dialog ──────────────────────────────────────────────
const showPolicyDialog = ref(false)
const policyEditing = ref(null)
const policyName = ref('')
const policyMatchPath = ref('')
const policyMatchHost = ref('')
const policySaving = ref(false)

watch(showPolicyDialog, (val) => {
  if (!val) { policyEditing.value = null }
})

function openCreatePolicy() {
  policyEditing.value = null
  policyName.value = ''
  policyMatchPath.value = ''
  policyMatchHost.value = ''
  showPolicyDialog.value = true
}

function openEditPolicy(policy) {
  policyEditing.value = policy
  policyName.value = policy.name || ''
  policyMatchPath.value = policy.tags?.TAG_SERVE_MATCH_PATH || ''
  policyMatchHost.value = policy.tags?.TAG_SERVE_MATCH_HOST || ''
  showPolicyDialog.value = true
}

async function handleSavePolicy(close) {
  policySaving.value = true
  try {
    const payload = {
      name: policyName.value,
      tags: {
        TAG_SERVE_MATCH_PATH: policyMatchPath.value,
        TAG_SERVE_MATCH_HOST: policyMatchHost.value,
      },
    }
    if (policyEditing.value) {
      await updatePolicy(policyEditing.value.id, payload)
      toast.success('Policy updated')
    } else {
      await createPolicy(payload)
      toast.success('Policy created')
    }
    close()
  } catch (e) {
    toast.error(e.message)
  } finally {
    policySaving.value = false
  }
}

function promptDeletePolicy(policy) {
  confirmDialog({
    title: 'Delete Policy?',
    message: `Are you sure you want to permanently remove "${policy.name || 'Unnamed'}"?`,
    theme: 'red',
    confirmLabel: 'Delete',
    onConfirm: async ({ hideDialog }) => {
      await deletePolicy(policy.id)
      toast.success('Policy deleted')
      hideDialog()
    },
  })
}

// ── User management ───────────────────────────────────────────────────────
const showUserDialog = ref(false)
const userName = ref('')
const userPassword = ref('')
const userEmail = ref('')
const userIsActive = ref(true)
const userIsAdmin = ref(false)
const userGroups = ref('')

watch(showUserDialog, (val) => {
  if (val) {
    userName.value = ''
    userPassword.value = ''
    userEmail.value = ''
    userIsActive.value = true
    userIsAdmin.value = false
    userGroups.value = ''
  }
})

async function handleCreateUser(close) {
  if (!userName.value.trim() || !userPassword.value.trim()) return
  try {
    await createUser({
      username: userName.value.trim(),
      password: userPassword.value,
      email: userEmail.value.trim(),
      is_active: userIsActive.value,
      is_superuser: userIsAdmin.value,
      groups: userGroups.value.split(',').map(s => s.trim()).filter(Boolean),
    })
    toast.success(`User "${userName.value}" created`)
    close()
  } catch (e) {
    toast.error(e.message || 'Failed to create user')
  }
}

// Edit User
const showEditUserDialog = ref(false)
const editingUser = ref(null)
const editUserEmail = ref('')
const editUserPassword = ref('')
const editUserIsActive = ref(true)
const editUserIsAdmin = ref(false)
const editUserGroups = ref('')
const userUpdating = ref(false)

function openEditUser(u) {
  editingUser.value = u
  editUserEmail.value = u.email || ''
  editUserPassword.value = ''
  editUserIsActive.value = u.is_active !== undefined ? u.is_active : true
  editUserIsAdmin.value = !!u.is_superuser
  editUserGroups.value = (u.groups || []).join(', ')
  showEditUserDialog.value = true
}

async function handleUpdateUser(close) {
  if (!editingUser.value) return
  userUpdating.value = true
  try {
    const payload = {
      email: editUserEmail.value.trim(),
      is_active: editUserIsActive.value,
      is_superuser: editUserIsAdmin.value,
      groups: editUserGroups.value.split(',').map(s => s.trim()).filter(Boolean),
    }
    if (editUserPassword.value.trim()) {
      payload.password = editUserPassword.value
    }
    await updateUser(editingUser.value.id, payload)
    toast.success(`User "${editingUser.value.username}" updated`)
    close()
  } catch (e) {
    toast.error(e.message || 'Failed to update user')
  } finally {
    userUpdating.value = false
  }
}

function promptDeleteUser(u) {
  confirmDialog({
    title: 'Delete User?',
    message: `Are you sure you want to permanently delete user "${u.username}"?`,
    theme: 'red',
    confirmLabel: 'Delete',
    onConfirm: async ({ hideDialog }) => {
      try {
        await deleteUser(u.id)
        toast.success(`User "${u.username}" deleted`)
        hideDialog()
      } catch (e) {
        toast.error(e.message || 'Failed to delete user')
      }
    },
  })
}

// ── Login Policy ───────────────────────────────────────────────────────────
const policyOptions = [
  { value: 'none', label: 'No requirement', description: 'Password alone is allowed' },
  { value: 'mfa_required', label: 'Require 2FA', description: 'Password + TOTP two-factor authentication required' },
  { value: 'sso_or_mfa', label: 'Require SSO or 2FA', description: 'No bare password — must sign in with SSO or password + 2FA' },
  { value: 'sso_required', label: 'Require SSO only', description: 'Password login completely disabled — SSO required' },
]

const globalPolicyReq = ref('none')
const globalPolicySaved = ref('none')
const globalPolicyId = ref(null)
const savingGlobalPolicy = ref(false)

const globalPolicyChanged = computed(() => globalPolicyReq.value !== globalPolicySaved.value)

const groupOverrides = computed(() => {
  return (authPolicies.value || []).filter(p => p.group_id !== null)
})

watch(() => authPolicies.value, (policies) => {
  const global = (policies || []).find(p => p.group_id === null)
  if (global) {
    globalPolicyReq.value = global.requirement
    globalPolicySaved.value = global.requirement
    globalPolicyId.value = global.id
  } else {
    globalPolicyReq.value = 'none'
    globalPolicySaved.value = 'none'
    globalPolicyId.value = null
  }
}, { immediate: true })

// Step-up password dialog for SSO_REQUIRED
const showStepUpDialog = ref(false)
const stepUpPassword = ref('')
const stepUpTargetReq = ref('')
const stepUpLoading = ref(false)

async function saveGlobalPolicy() {
  const req = globalPolicyReq.value
  if (req === 'sso_required') {
    stepUpPassword.value = ''
    stepUpTargetReq.value = req
    showStepUpDialog.value = true
    return
  }

  if (req !== 'none') {
    const { count } = await getAffectedCount(req)
    confirmDialog({
      title: 'Change Organization Login Policy?',
      message: `This will affect ${count} active non-superuser user(s). Superusers are always exempt to prevent accidental lockout.`,
      theme: 'orange',
      confirmLabel: 'Apply Policy',
      onConfirm: async ({ hideDialog }) => {
        await executeSaveGlobal(req, null)
        hideDialog()
      },
    })
    return
  }

  await executeSaveGlobal(req, null)
}

async function handleConfirmStepUp(close) {
  if (!stepUpPassword.value.trim()) return
  stepUpLoading.value = true
  try {
    await executeSaveGlobal(stepUpTargetReq.value, stepUpPassword.value)
    close()
  } catch (e) {
    toast.error(e.message || 'Incorrect password')
  } finally {
    stepUpLoading.value = false
  }
}

async function executeSaveGlobal(req, confirmPass) {
  savingGlobalPolicy.value = true
  try {
    if (globalPolicyId.value) {
      await updateAuthPolicy(globalPolicyId.value, {
        requirement: req,
        confirm_password: confirmPass,
      })
    } else {
      await createAuthPolicy({ requirement: req })
    }
    globalPolicySaved.value = req
    toast.success('Organization login policy updated')
  } catch (e) {
    toast.error(e.message || 'Failed to update policy')
  } finally {
    savingGlobalPolicy.value = false
  }
}

function policyLabel(req) {
  return policyOptions.find(o => o.value === req)?.label || req
}

// Override dialog
const showOverrideDialog = ref(false)
const overrideEditing = ref(null)
const overrideGroupId = ref('')
const overrideReq = ref('mfa_required')
const overrideSaving = ref(false)

function openAddOverride() {
  overrideEditing.value = null
  overrideGroupId.value = groups.value?.[0]?.id ? String(groups.value[0].id) : ''
  overrideReq.value = 'mfa_required'
  showOverrideDialog.value = true
}

function openEditOverride(policy) {
  overrideEditing.value = policy
  overrideGroupId.value = String(policy.group_id)
  overrideReq.value = policy.requirement
  showOverrideDialog.value = true
}

async function handleSaveOverride(close) {
  overrideSaving.value = true
  try {
    if (overrideEditing.value) {
      await updateAuthPolicy(overrideEditing.value.id, {
        requirement: overrideReq.value,
      })
      toast.success('Override updated')
    } else {
      if (!overrideGroupId.value) {
        toast.error('Please specify a group')
        overrideSaving.value = false
        return
      }
      await createAuthPolicy({
        group_id: Number(overrideGroupId.value),
        requirement: overrideReq.value,
      })
      toast.success('Group override added')
    }
    close()
  } catch (e) {
    toast.error(e.message || 'Failed to save override')
  } finally {
    overrideSaving.value = false
  }
}

function promptDeleteOverride(policy) {
  confirmDialog({
    title: 'Remove Override?',
    message: `Remove the login policy override for group "${policy.group_name}"? Members will fall back to the organization default.`,
    theme: 'red',
    confirmLabel: 'Remove',
    onConfirm: async ({ hideDialog }) => {
      await deleteAuthPolicy(policy.id)
      toast.success('Group override removed')
      hideDialog()
    },
  })
}

// ── SSO Providers ──────────────────────────────────────────────────────────
const showSsoDialog = ref(false)
const ssoEditing = ref(null)
const ssoProvider = ref('google')
const ssoName = ref('')
const ssoClientId = ref('')
const ssoClientSecret = ref('')
const ssoSaving = ref(false)

function openAddSso() {
  ssoEditing.value = null
  ssoProvider.value = availableProviders.value?.[0]?.id || 'google'
  ssoName.value = availableProviders.value?.[0]?.name || 'Google'
  ssoClientId.value = ''
  ssoClientSecret.value = ''
  showSsoDialog.value = true
}

function openEditSso(app) {
  ssoEditing.value = app
  ssoProvider.value = app.provider
  ssoName.value = app.name
  ssoClientId.value = app.client_id
  ssoClientSecret.value = ''
  showSsoDialog.value = true
}

async function handleSaveSso(close) {
  if (!ssoName.value.trim() || !ssoClientId.value.trim()) return
  if (!ssoEditing.value && !ssoClientSecret.value.trim()) {
    toast.error('Client secret is required')
    return
  }
  ssoSaving.value = true
  try {
    if (ssoEditing.value) {
      const payload = {
        name: ssoName.value.trim(),
        client_id: ssoClientId.value.trim(),
      }
      if (ssoClientSecret.value.trim()) {
        payload.client_secret = ssoClientSecret.value.trim()
      }
      await updateSsoProvider(ssoEditing.value.id, payload)
      toast.success(`SSO Provider "${ssoName.value}" updated`)
    } else {
      await createSsoProvider({
        provider: ssoProvider.value,
        name: ssoName.value.trim(),
        client_id: ssoClientId.value.trim(),
        client_secret: ssoClientSecret.value.trim(),
      })
      toast.success(`SSO Provider "${ssoName.value}" added`)
    }
    close()
  } catch (e) {
    toast.error(e.message || 'Failed to save SSO provider')
  } finally {
    ssoSaving.value = false
  }
}

function promptDeleteSso(app) {
  confirmDialog({
    title: 'Remove SSO Provider?',
    message: `Remove SSO credentials for "${app.name}"? Users will no longer be able to log in with this provider.`,
    theme: 'red',
    confirmLabel: 'Remove',
    onConfirm: async ({ hideDialog }) => {
      await deleteSsoProvider(app.id)
      toast.success(`SSO Provider "${app.name}" removed`)
      hideDialog()
    },
  })
}

// ── SSO sign-in rules ──────────────────────────────────────────────────────
const ssoRuleDomains = ref('')
const ssoRuleJit = ref(false)
const ssoRulesSaving = ref(false)

watch(() => ssoSettings.value, (v) => {
  ssoRuleDomains.value = v?.allowed_email_domains || ''
  ssoRuleJit.value = !!v?.allow_jit_signup
}, { immediate: true, deep: true })

const ssoRulesChanged = computed(() =>
  ssoRuleDomains.value !== (ssoSettings.value?.allowed_email_domains || '') ||
  ssoRuleJit.value !== !!ssoSettings.value?.allow_jit_signup,
)

async function handleSaveSsoRules() {
  ssoRulesSaving.value = true
  try {
    await saveSsoSettings({
      allowed_email_domains: ssoRuleDomains.value,
      allow_jit_signup: ssoRuleJit.value,
    })
    toast.success('SSO sign-in rules saved')
  } catch (e) {
    toast.error(e.message || 'Failed to save SSO rules')
  } finally {
    ssoRulesSaving.value = false
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────
function copyToClipboard(text) {
  navigator.clipboard.writeText(text)
  toast.success('Copied to clipboard')
}

// ── MFA (TOTP 2FA) enrollment dialog ────────────────────────────────────────
const showMfaSetupDialog = ref(false)
const mfaSetupData = ref(null) // { secret, otpauth_url, qr_svg }
const mfaConfirmCode = ref('')
const mfaRecoveryCodes = ref(null)

async function startMfaSetup() {
  try {
    mfaSetupData.value = await setupMfa()
    mfaConfirmCode.value = ''
    mfaRecoveryCodes.value = null
    showMfaSetupDialog.value = true
  } catch (e) {
    toast.error(e.message || 'Failed to start 2FA setup')
  }
}

async function handleConfirmMfa() {
  try {
    const result = await confirmMfa(mfaConfirmCode.value)
    mfaRecoveryCodes.value = result.recovery_codes
    toast.success('Two-factor authentication enabled')
  } catch (e) {
    toast.error(e.message || 'Incorrect code')
  }
}

const pwForm = ref({ current: '', next: '', confirm: '' })
const pwChanging = ref(false)

async function handleChangePassword() {
  const { current, next, confirm } = pwForm.value
  if (next !== confirm) {
    toast.error('The two new passwords do not match')
    return
  }
  pwChanging.value = true
  try {
    await changeOwnPassword(current, next)
    pwForm.value = { current: '', next: '', confirm: '' }
    toast.success('Password changed. Other sessions were signed out.')
  } catch (e) {
    toast.error(e.message || 'Could not change the password')
  } finally {
    pwChanging.value = false
  }
}

const showMfaDisableDialog = ref(false)
const mfaDisablePassword = ref('')

watch(showMfaDisableDialog, (val) => { if (val) mfaDisablePassword.value = '' })

async function handleDisableMfa(close) {
  try {
    await disableMfa(mfaDisablePassword.value)
    toast.success('Two-factor authentication disabled')
    close()
  } catch (e) {
    toast.error(e.message || 'Incorrect password')
  }
}
</script>

<template>
  <div class="flex h-full flex-col">
    <!-- Header -->
    <header class="sticky top-0 z-10 flex min-h-12 items-center justify-between border-b border-outline-gray-1 bg-surface-white px-3 sm:px-5">
      <h1 class="text-2xl font-semibold text-ink-gray-9">Settings</h1>
    </header>

    <!-- Tabs -->
    <nav class="border-b border-outline-gray-1 bg-surface-white px-3 sm:px-5">
      <TabButtons
        v-model="activeTab"
        :buttons="tabs"
      />
    </nav>

    <!-- Content -->
    <div class="flex-1 overflow-auto px-3 pt-5 pb-40 sm:px-5">
      <div class="mx-auto w-full max-w-[800px]">

        <!-- ═══ API Keys ═══ -->
        <div v-if="activeTab === 'keys'" class="space-y-4">
          <div class="flex items-center justify-between">
            <h2 class="text-base font-medium text-ink-gray-8">API Keys</h2>
            <Button variant="solid" theme="gray" icon-left="plus" label="Create Key" @click="showKeyDialog = true" />
          </div>

          <div v-if="keysLoading" class="py-8 text-center text-sm text-ink-gray-5">Loading...</div>

          <div v-else class="divide-y divide-outline-gray-1 rounded-md border border-outline-gray-1 overflow-hidden">
            <div
              v-for="key in apiKeys"
              :key="key.id"
              class="flex items-center justify-between bg-surface-white px-4 py-3"
            >
              <div class="min-w-0">
                <p class="text-sm font-medium text-ink-gray-9">{{ key.name }}</p>
                <p class="text-xs text-ink-gray-5 font-mono">{{ key.access_key }}</p>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <Button icon="copy" variant="ghost" size="sm" @click="copyToClipboard(key.access_key)" />
                <Button icon="trash-2" variant="ghost" theme="red" size="sm" @click="promptDeleteKey(key)" />
              </div>
            </div>
            <div v-if="!apiKeys.length" class="px-4 py-8 text-center text-p-sm text-ink-gray-5">
              No API keys yet.
            </div>
          </div>

          <!-- New secret display -->
          <div v-if="newSecret" class="rounded-md border border-orange-300 bg-orange-50 p-4">
            <p class="text-sm font-medium text-orange-800 mb-1">Secret Key — shown only once!</p>
            <p class="text-sm font-mono text-orange-700 break-all">{{ newSecret }}</p>
            <div class="mt-2 flex gap-2">
              <Button size="sm" label="Copy" @click="copyToClipboard(newSecret)" />
              <Button size="sm" label="Dismiss" variant="ghost" @click="newSecret = ''" />
            </div>
          </div>
        </div>

        <!-- ═══ Users ═══ -->
        <div v-if="isSuperAdmin && activeTab === 'users'" class="space-y-4">
          <div class="flex items-center justify-between">
            <h2 class="text-base font-medium text-ink-gray-8">Users</h2>
            <Button variant="solid" theme="gray" icon-left="plus" label="Create User" @click="showUserDialog = true" />
          </div>

          <div v-if="usersLoading" class="py-8 text-center text-sm text-ink-gray-5">Loading...</div>

          <div v-else class="divide-y divide-outline-gray-1 rounded-md border border-outline-gray-1 overflow-hidden">
            <div
              v-for="u in users"
              :key="u.id"
              class="flex items-center justify-between bg-surface-white px-4 py-3"
            >
              <div>
                <div class="flex items-center gap-2">
                  <p class="text-sm font-medium text-ink-gray-9">{{ u.username }}</p>
                  <Badge :label="u.is_superuser ? 'Admin' : 'User'" :theme="u.is_superuser ? 'red' : 'gray'" variant="subtle" size="sm" />
                  <Badge :label="u.is_active ? 'Active' : 'Inactive'" :theme="u.is_active ? 'green' : 'orange'" variant="subtle" size="sm" />
                </div>
                <p class="text-xs text-ink-gray-5">
                  {{ u.email || 'No email' }}
                  <span v-if="u.groups && u.groups.length"> · Groups: {{ u.groups.join(', ') }}</span>
                </p>
              </div>
              <div class="flex items-center gap-2">
                <Button icon="edit-2" variant="ghost" size="sm" @click="openEditUser(u)" />
                <Button icon="trash-2" variant="ghost" theme="red" size="sm" @click="promptDeleteUser(u)" />
              </div>
            </div>
            <div v-if="!users.length" class="px-4 py-8 text-center text-p-sm text-ink-gray-5">
              No users yet.
            </div>
          </div>
        </div>

        <!-- ═══ Security (2FA) ═══ -->
        <div v-if="activeTab === 'security'" class="space-y-4">
          <h2 class="text-base font-medium text-ink-gray-8">Two-Factor Authentication</h2>
          <p class="text-p-sm text-ink-gray-5">
            Require a time-based one-time password (TOTP) from an authenticator
            app in addition to your password. This is a per-account setting —
            alternatively you can sign in with a social/SSO provider from the
            login page instead of a password + 2FA.
          </p>

          <div v-if="mfaStatusLoading" class="py-8 text-center text-sm text-ink-gray-5">Loading...</div>

          <div v-else class="rounded-md border border-outline-gray-1 bg-surface-white p-4">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <Badge :label="mfaEnabled ? 'Enabled' : 'Disabled'" :theme="mfaEnabled ? 'green' : 'gray'" variant="subtle" size="sm" />
                <span class="text-sm text-ink-gray-7">Authenticator app (TOTP)</span>
              </div>
              <Button
                v-if="!mfaEnabled"
                variant="solid" theme="gray" label="Enable 2FA"
                :loading="mfaSettingUp"
                @click="startMfaSetup"
              />
              <Button
                v-else
                variant="outline" theme="red" label="Disable 2FA"
                @click="showMfaDisableDialog = true"
              />
            </div>
          </div>
        </div>

        <!-- ═══ Change password ═══ -->
        <div v-if="activeTab === 'security'" class="mt-8 space-y-4">
          <h2 class="text-base font-medium text-ink-gray-8">Change Password</h2>
          <p class="text-p-sm text-ink-gray-5">
            Changing your password signs you out everywhere else.
          </p>
          <form
            class="max-w-sm space-y-3 rounded-md border border-outline-gray-1 bg-surface-white p-4"
            @submit.prevent="handleChangePassword"
          >
            <FormControl v-model="pwForm.current" type="password" label="Current password" autocomplete="current-password" required />
            <FormControl v-model="pwForm.next" type="password" label="New password" autocomplete="new-password" required />
            <FormControl v-model="pwForm.confirm" type="password" label="Confirm new password" autocomplete="new-password" required />
            <Button variant="solid" theme="gray" type="submit" label="Change password" :loading="pwChanging" />
          </form>
        </div>

        <!-- ═══ Login Policy ═══ -->
        <div v-if="isSuperAdmin && activeTab === 'login-policy'" class="space-y-6">
          <div>
            <h2 class="text-base font-medium text-ink-gray-8">Organization Login Policy</h2>
            <p class="text-p-sm text-ink-gray-5 mt-1">
              Set the organization-wide default login requirement for all users.
              Per-group overrides take precedence over the default.
            </p>
          </div>

          <div class="rounded-md border border-outline-gray-1 bg-surface-white p-5 space-y-4">
            <div class="space-y-3">
              <label
                v-for="opt in policyOptions"
                :key="opt.value"
                class="flex items-start gap-3 p-3 rounded-md border border-outline-gray-1 hover:bg-surface-gray-1 cursor-pointer transition-colors"
                :class="{ 'border-gray-900 bg-surface-gray-1': globalPolicyReq === opt.value }"
              >
                <input
                  type="radio"
                  name="globalPolicy"
                  :value="opt.value"
                  v-model="globalPolicyReq"
                  class="mt-1 text-gray-900 focus:ring-gray-900"
                />
                <div>
                  <p class="text-sm font-medium text-ink-gray-9">{{ opt.label }}</p>
                  <p class="text-xs text-ink-gray-5">{{ opt.description }}</p>
                </div>
              </label>
            </div>

            <div class="rounded-md bg-blue-50 border border-blue-200 p-3 flex items-start gap-2">
              <FeatherIcon name="info" class="h-4 w-4 text-blue-600 mt-0.5 shrink-0" />
              <p class="text-xs text-blue-800">
                <strong>Superuser Exemption:</strong> Superusers are always exempt from login policies to prevent accidental lockouts. Policies apply to all non-admin accounts.
              </p>
            </div>

            <div class="flex items-center gap-3 pt-2">
              <Button
                variant="solid"
                theme="gray"
                label="Save Default Policy"
                :loading="savingGlobalPolicy"
                :disabled="!globalPolicyChanged"
                @click="saveGlobalPolicy"
              />
              <span v-if="globalPolicyChanged" class="text-xs text-orange-600">Unsaved changes</span>
            </div>
          </div>

          <!-- Per-Group Overrides -->
          <div class="space-y-4 pt-4">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-base font-medium text-ink-gray-8">Per-Group Overrides</h3>
                <p class="text-xs text-ink-gray-5 mt-0.5">
                  Users who belong to a group with an override will follow the group policy instead of the default.
                </p>
              </div>
              <Button variant="solid" theme="gray" icon-left="plus" label="Add Override" @click="openAddOverride" />
            </div>

            <div v-if="authPoliciesLoading" class="py-8 text-center text-sm text-ink-gray-5">Loading...</div>

            <div v-else class="divide-y divide-outline-gray-1 rounded-md border border-outline-gray-1 overflow-hidden">
              <div
                v-for="p in groupOverrides"
                :key="p.id"
                class="flex items-center justify-between bg-surface-white px-4 py-3"
              >
                <div>
                  <div class="flex items-center gap-2">
                    <FeatherIcon name="users" class="h-4 w-4 text-ink-gray-5" />
                    <p class="text-sm font-medium text-ink-gray-9">{{ p.group_name }}</p>
                  </div>
                  <p class="text-xs text-ink-gray-5 mt-0.5">Requirement: <span class="font-medium text-ink-gray-8">{{ policyLabel(p.requirement) }}</span></p>
                </div>
                <div class="flex items-center gap-2">
                  <Button icon="edit-2" variant="ghost" size="sm" @click="openEditOverride(p)" />
                  <Button icon="trash-2" variant="ghost" theme="red" size="sm" @click="promptDeleteOverride(p)" />
                </div>
              </div>
              <div v-if="!groupOverrides.length" class="px-4 py-8 text-center text-p-sm text-ink-gray-5">
                No group overrides configured. All users follow the organization default.
              </div>
            </div>
          </div>
        </div>

        <!-- ═══ SSO Providers ═══ -->
        <div v-if="isSuperAdmin && activeTab === 'sso-providers'" class="space-y-4">
          <div class="flex items-center justify-between">
            <div>
              <h2 class="text-base font-medium text-ink-gray-8">SSO Providers</h2>
              <p class="text-p-sm text-ink-gray-5 mt-0.5">
                Manage OAuth2 / OpenID Connect credentials for third-party identity providers.
              </p>
            </div>
            <Button variant="solid" theme="gray" icon-left="plus" label="Add Provider" @click="openAddSso" />
          </div>

          <div v-if="ssoProvidersLoading" class="py-8 text-center text-sm text-ink-gray-5">Loading...</div>

          <div v-else class="divide-y divide-outline-gray-1 rounded-md border border-outline-gray-1 overflow-hidden">
            <div
              v-for="app in ssoProviders"
              :key="app.id"
              class="flex items-center justify-between bg-surface-white px-4 py-3"
            >
              <div class="min-w-0">
                <div class="flex items-center gap-2">
                  <p class="text-sm font-medium text-ink-gray-9">{{ app.name }}</p>
                  <Badge :label="app.provider" theme="blue" variant="subtle" size="sm" />
                </div>
                <p class="text-xs text-ink-gray-5 font-mono truncate max-w-[400px]">Client ID: {{ app.client_id }}</p>
                <div class="flex items-center gap-1.5 mt-1">
                  <span class="text-xs text-ink-gray-4">Callback:</span>
                  <code class="text-xs text-ink-gray-6 font-mono bg-surface-gray-2 px-1.5 py-0.5 rounded">{{ app.callback_url }}</code>
                  <Button icon="copy" variant="ghost" size="sm" @click="copyToClipboard(app.callback_url)" />
                </div>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <Button icon="edit-2" variant="ghost" size="sm" @click="openEditSso(app)" />
                <Button icon="trash-2" variant="ghost" theme="red" size="sm" @click="promptDeleteSso(app)" />
              </div>
            </div>
            <div v-if="!ssoProviders.length" class="px-4 py-8 text-center text-p-sm text-ink-gray-5">
              No SSO providers configured yet. Click "Add Provider" to connect Google, GitHub, or Microsoft.
            </div>
          </div>

          <!-- Sign-in rules -->
          <div class="rounded-md border border-outline-gray-1 bg-surface-white p-5 space-y-4">
            <div>
              <h3 class="text-base font-medium text-ink-gray-8">Sign-in rules</h3>
              <p class="text-xs text-ink-gray-5 mt-0.5">
                A user whose provider-verified email matches an existing p2 user is linked to
                that user on first SSO sign-in. These rules control everyone else.
              </p>
            </div>
            <FormControl
              v-model="ssoRuleDomains"
              label="Allowed email domains"
              type="text"
              placeholder="example.com, example.org (leave empty to allow any domain)"
            />
            <label class="flex items-start gap-3 cursor-pointer">
              <input type="checkbox" v-model="ssoRuleJit" class="mt-1" />
              <span>
                <span class="block text-sm font-medium text-ink-gray-9">Create users on first SSO sign-in</span>
                <span class="block text-xs text-ink-gray-5">
                  Off: only people you have already created can sign in with SSO.
                  On: anyone with a verified email in the allowed domains gets an account
                  with no bucket access until you grant it.
                </span>
              </span>
            </label>
            <div class="flex items-center gap-3">
              <Button
                variant="solid" theme="gray" label="Save rules"
                :loading="ssoRulesSaving" :disabled="!ssoRulesChanged"
                @click="handleSaveSsoRules"
              />
              <span v-if="ssoRulesChanged" class="text-xs text-orange-600">Unsaved changes</span>
            </div>
          </div>
        </div>

        <!-- ═══ Serve Rules (admin only) ═══ -->
        <div v-if="isSuperAdmin && activeTab === 'policies'" class="space-y-4">
          <div class="flex items-center justify-between">
            <h2 class="text-base font-medium text-ink-gray-8">Serve Rules</h2>
            <Button variant="solid" theme="gray" icon-left="plus" label="Add Rule" @click="openCreatePolicy" />
          </div>

          <div v-if="policiesLoading" class="py-8 text-center text-sm text-ink-gray-5">Loading...</div>

          <div v-else class="divide-y divide-outline-gray-1 rounded-md border border-outline-gray-1 overflow-hidden">
            <div
              v-for="p in policies"
              :key="p.id"
              class="flex items-center justify-between bg-surface-white px-4 py-3"
            >
              <div class="min-w-0">
                <p class="text-sm font-medium text-ink-gray-9">{{ p.name || 'Unnamed Rule' }}</p>
                <p class="text-xs text-ink-gray-5">
                  <span v-if="p.tags?.TAG_SERVE_MATCH_PATH">Path: {{ p.tags.TAG_SERVE_MATCH_PATH }}</span>
                  <span v-if="p.tags?.TAG_SERVE_MATCH_HOST"> · Host: {{ p.tags.TAG_SERVE_MATCH_HOST }}</span>
                </p>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <Button icon="edit" variant="ghost" size="sm" @click="openEditPolicy(p)" />
                <Button icon="trash-2" variant="ghost" theme="red" size="sm" @click="promptDeletePolicy(p)" />
              </div>
            </div>
            <div v-if="!policies.length" class="px-4 py-8 text-center text-p-sm text-ink-gray-5">
              No policies defined yet.
            </div>
          </div>
        </div>

        <!-- ═══ System ═══ -->
        <div v-if="activeTab === 'config'" class="space-y-6">
          <h2 class="text-base font-medium text-ink-gray-8">System Configuration</h2>

          <div v-if="configLoading" class="py-8 text-center text-sm text-ink-gray-5">Loading...</div>

          <div v-else class="space-y-4">
            <div class="rounded-md border border-outline-gray-1 bg-surface-white p-4">
              <p class="text-xs text-ink-gray-5 mb-1">S3 Endpoint</p>
              <p class="text-sm font-mono text-ink-gray-9">{{ config.s3_endpoint || 'localhost' }}</p>
            </div>
            <div class="rounded-md border border-outline-gray-1 bg-surface-white p-4">
              <p class="text-xs text-ink-gray-5 mb-1">Version</p>
              <p class="text-sm font-mono text-ink-gray-9">{{ config.version }}</p>
            </div>
            <div class="rounded-md border border-outline-gray-1 bg-surface-white p-4">
              <p class="text-xs text-ink-gray-5 mb-2">Storage Classes</p>
              <div class="flex flex-wrap gap-2">
                <Badge v-for="sc in config.storage_classes" :key="sc.value" :label="sc.label" theme="gray" variant="subtle" size="sm" />
              </div>
            </div>
            <div class="rounded-md border border-outline-gray-1 bg-surface-white p-4">
              <p class="text-xs text-ink-gray-5 mb-2">Encryption Options</p>
              <div class="flex flex-wrap gap-2">
                <Badge v-for="enc in config.encryption_options" :key="enc.value" :label="enc.label" theme="gray" variant="subtle" size="sm" />
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>

    <!-- ═══ Dialogs ═══ -->

    <!-- Create API Key -->
    <Dialog v-model="showKeyDialog" :key="'key-' + showKeyDialog" :options="{ title: 'Create API Key', icon: { name: 'key' }, size: 'lg' }">
      <template #body-content>
        <div class="space-y-4" @pointerdown.stop>
          <FormControl
            v-model="keyFormName"
            label="Key Name"
            type="text"
            placeholder="My API Key"
            required
          />
        </div>
      </template>
      <template #actions="{ close }">
        <div class="flex justify-end gap-2 w-full">
          <Button label="Cancel" @click="close" />
          <Button
            variant="solid" theme="gray" label="Create"
            :loading="keyCreating" :disabled="!keyFormName.trim()"
            @click="handleCreateKey(close)"
          />
        </div>
      </template>
    </Dialog>

    <!-- Create/Edit Policy -->
    <Dialog v-model="showPolicyDialog" :key="'policy-' + showPolicyDialog" :options="{ title: policyEditing ? 'Edit Policy' : 'Create Policy', icon: { name: 'shield' }, size: 'lg' }">
      <template #body-content>
        <div class="space-y-4" @pointerdown.stop>
          <FormControl v-model="policyName" label="Rule Name" type="text" placeholder="my-rule" />
          <FormControl v-model="policyMatchPath" label="Match Path (regex)" type="text" placeholder="/public/*" />
          <FormControl v-model="policyMatchHost" label="Match Host (regex)" type="text" placeholder="*.example.com" />
        </div>
      </template>
      <template #actions="{ close }">
        <div class="flex justify-end gap-2 w-full">
          <Button label="Cancel" @click="close" />
          <Button
            variant="solid" theme="gray" :label="policyEditing ? 'Update' : 'Create'"
            :loading="policySaving"
            @click="handleSavePolicy(close)"
          />
        </div>
      </template>
    </Dialog>

    <!-- Enable 2FA (QR + confirm) -->
    <Dialog v-model="showMfaSetupDialog" :key="'mfa-setup-' + showMfaSetupDialog" :options="{ title: 'Enable Two-Factor Authentication', icon: { name: 'shield' }, size: 'lg' }">
      <template #body-content>
        <div class="space-y-4" @pointerdown.stop>
          <template v-if="!mfaRecoveryCodes">
            <p class="text-p-sm text-ink-gray-6">
              Scan this QR code with your authenticator app (Google Authenticator,
              Authy, 1Password, etc.), then enter the 6-digit code it generates.
            </p>
            <div v-if="mfaSetupData" class="flex justify-center rounded-md border border-outline-gray-1 bg-white p-4" v-html="mfaSetupData.qr_svg" />
            <p v-if="mfaSetupData" class="text-center text-p-xs font-mono text-ink-gray-5 break-all">
              {{ mfaSetupData.secret }}
            </p>
            <FormControl
              v-model="mfaConfirmCode"
              label="6-digit code"
              type="text"
              placeholder="123456"
              autocomplete="one-time-code"
            />
          </template>
          <template v-else>
            <p class="text-p-sm font-medium text-ink-gray-9">
              Save these recovery codes somewhere safe — each can be used once
              to sign in if you lose access to your authenticator app. They
              will not be shown again.
            </p>
            <div class="grid grid-cols-2 gap-2 rounded-md border border-outline-gray-1 bg-surface-gray-1 p-4 font-mono text-sm">
              <span v-for="rc in mfaRecoveryCodes" :key="rc">{{ rc }}</span>
            </div>
            <Button label="Copy all" @click="copyToClipboard(mfaRecoveryCodes.join('\n'))" />
          </template>
        </div>
      </template>
      <template #actions="{ close }">
        <div class="flex justify-end gap-2 w-full">
          <Button v-if="!mfaRecoveryCodes" label="Cancel" @click="close" />
          <Button
            v-if="!mfaRecoveryCodes"
            variant="solid" theme="gray" label="Verify & Enable"
            :loading="mfaConfirming" :disabled="!mfaConfirmCode.trim()"
            @click="handleConfirmMfa"
          />
          <Button v-else variant="solid" theme="gray" label="Done" @click="close" />
        </div>
      </template>
    </Dialog>

    <!-- Disable 2FA -->
    <Dialog v-model="showMfaDisableDialog" :key="'mfa-disable-' + showMfaDisableDialog" :options="{ title: 'Disable Two-Factor Authentication', icon: { name: 'shield-off' }, size: 'lg' }">
      <template #body-content>
        <div class="space-y-4" @pointerdown.stop>
          <p class="text-p-sm text-ink-gray-6">
            Confirm your password to turn off two-factor authentication.
          </p>
          <FormControl
            v-model="mfaDisablePassword"
            type="password"
            label="Password"
            placeholder="••••••••"
            required
          />
        </div>
      </template>
      <template #actions="{ close }">
        <div class="flex justify-end gap-2 w-full">
          <Button label="Cancel" @click="close" />
          <Button
            variant="solid" theme="red" label="Disable 2FA"
            :loading="mfaDisabling" :disabled="!mfaDisablePassword.trim()"
            @click="handleDisableMfa(close)"
          />
        </div>
      </template>
    </Dialog>

    <!-- Create User -->
    <Dialog v-model="showUserDialog" :key="'user-' + showUserDialog" :options="{ title: 'Create User', icon: { name: 'user-plus' }, size: 'lg' }">
      <template #body-content>
        <div class="space-y-4" @pointerdown.stop>
          <FormControl
            v-model="userName"
            label="Username"
            type="text"
            placeholder="jdoe"
            required
          />
          <FormControl
            v-model="userPassword"
            type="password"
            label="Password"
            placeholder="••••••••"
            required
          />
          <FormControl
            v-model="userEmail"
            label="Email"
            type="text"
            placeholder="jdoe@example.com"
          />
          <FormControl
            v-model="userGroups"
            label="Groups (comma-separated)"
            type="text"
            placeholder="engineering, devops"
          />
          <div class="flex items-center gap-4">
            <FormControl
              v-model="userIsActive"
              type="checkbox"
              label="Active"
            />
            <FormControl
              v-model="userIsAdmin"
              type="checkbox"
              label="Superuser (admin)"
            />
          </div>
        </div>
      </template>
      <template #actions="{ close }">
        <div class="flex justify-end gap-2 w-full">
          <Button label="Cancel" @click="close" />
          <Button
            variant="solid" theme="gray" label="Create User"
            :loading="userCreating" :disabled="!userName.trim() || !userPassword.trim()"
            @click="handleCreateUser(close)"
          />
        </div>
      </template>
    </Dialog>

    <!-- Edit User -->
    <Dialog v-model="showEditUserDialog" :key="'edit-user-' + showEditUserDialog" :options="{ title: `Edit User: ${editingUser?.username}`, icon: { name: 'user-check' }, size: 'lg' }">
      <template #body-content>
        <div class="space-y-4" @pointerdown.stop>
          <FormControl
            v-model="editUserEmail"
            label="Email"
            type="text"
            placeholder="user@example.com"
          />
          <FormControl
            v-model="editUserPassword"
            type="password"
            label="New Password (leave blank to keep current)"
            placeholder="••••••••"
          />
          <FormControl
            v-model="editUserGroups"
            label="Groups (comma-separated)"
            type="text"
            placeholder="engineering, devops"
          />
          <div class="flex items-center gap-4">
            <FormControl
              v-model="editUserIsActive"
              type="checkbox"
              label="Active"
            />
            <FormControl
              v-model="editUserIsAdmin"
              type="checkbox"
              label="Superuser (admin)"
            />
          </div>
        </div>
      </template>
      <template #actions="{ close }">
        <div class="flex justify-end gap-2 w-full">
          <Button label="Cancel" @click="close" />
          <Button
            variant="solid" theme="gray" label="Save Changes"
            :loading="userUpdating"
            @click="handleUpdateUser(close)"
          />
        </div>
      </template>
    </Dialog>

    <!-- Step-Up Password Confirmation Dialog (for SSO_REQUIRED) -->
    <Dialog v-model="showStepUpDialog" :key="'step-up-' + showStepUpDialog" :options="{ title: 'Confirm Password for SSO-Only Policy', icon: { name: 'shield-alert' }, size: 'md' }">
      <template #body-content>
        <div class="space-y-3" @pointerdown.stop>
          <p class="text-p-sm text-ink-gray-6">
            Disabling password login across the organization requires step-up authentication. Please enter your administrator password to proceed.
          </p>
          <FormControl
            v-model="stepUpPassword"
            type="password"
            label="Admin Password"
            placeholder="••••••••"
            required
          />
        </div>
      </template>
      <template #actions="{ close }">
        <div class="flex justify-end gap-2 w-full">
          <Button label="Cancel" @click="close" />
          <Button
            variant="solid" theme="red" label="Confirm & Apply"
            :loading="stepUpLoading" :disabled="!stepUpPassword.trim()"
            @click="handleConfirmStepUp(close)"
          />
        </div>
      </template>
    </Dialog>

    <!-- Add / Edit Group Override Dialog -->
    <Dialog v-model="showOverrideDialog" :key="'override-' + showOverrideDialog" :options="{ title: overrideEditing ? 'Edit Group Policy Override' : 'Add Group Policy Override', icon: { name: 'shield' }, size: 'lg' }">
      <template #body-content>
        <div class="space-y-4" @pointerdown.stop>
          <div v-if="!overrideEditing">
            <label class="block text-xs font-medium text-ink-gray-5 mb-1">Group</label>
            <select
              v-if="groups && groups.length"
              v-model="overrideGroupId"
              class="w-full rounded-md border border-outline-gray-1 bg-surface-white px-3 py-2 text-sm text-ink-gray-9 focus:border-gray-900 focus:outline-none"
            >
              <option v-for="g in groups" :key="g.id" :value="String(g.id)">
                {{ g.name }} ({{ g.user_count }} member{{ g.user_count !== 1 ? 's' : '' }})
              </option>
            </select>
            <FormControl
              v-else
              v-model="overrideGroupId"
              label="Group ID"
              type="text"
              placeholder="e.g. 1"
              required
            />
          </div>
          <div v-else>
            <p class="text-sm font-medium text-ink-gray-9">Group: {{ overrideEditing.group_name }}</p>
          </div>

          <div>
            <label class="block text-xs font-medium text-ink-gray-5 mb-1">Requirement</label>
            <select
              v-model="overrideReq"
              class="w-full rounded-md border border-outline-gray-1 bg-surface-white px-3 py-2 text-sm text-ink-gray-9 focus:border-gray-900 focus:outline-none"
            >
              <option v-for="opt in policyOptions" :key="opt.value" :value="opt.value">
                {{ opt.label }} — {{ opt.description }}
              </option>
            </select>
          </div>
        </div>
      </template>
      <template #actions="{ close }">
        <div class="flex justify-end gap-2 w-full">
          <Button label="Cancel" @click="close" />
          <Button
            variant="solid" theme="gray" :label="overrideEditing ? 'Update Override' : 'Create Override'"
            :loading="overrideSaving"
            @click="handleSaveOverride(close)"
          />
        </div>
      </template>
    </Dialog>

    <!-- Add / Edit SSO Provider Dialog -->
    <Dialog v-model="showSsoDialog" :key="'sso-' + showSsoDialog" :options="{ title: ssoEditing ? 'Edit SSO Provider' : 'Add SSO Provider', icon: { name: 'globe' }, size: 'lg' }">
      <template #body-content>
        <div class="space-y-4" @pointerdown.stop>
          <div v-if="!ssoEditing">
            <label class="block text-xs font-medium text-ink-gray-5 mb-1">Provider Type</label>
            <select
              v-model="ssoProvider"
              class="w-full rounded-md border border-outline-gray-1 bg-surface-white px-3 py-2 text-sm text-ink-gray-9 focus:border-gray-900 focus:outline-none"
              @change="ssoName = availableProviders.find(p => p.id === ssoProvider)?.name || ssoProvider"
            >
              <option v-for="p in availableProviders" :key="p.id" :value="p.id">
                {{ p.name }} ({{ p.id }})
              </option>
            </select>
          </div>

          <FormControl
            v-model="ssoName"
            label="Button Text (shown on the login page)"
            type="text"
            placeholder="Sign in with Google"
            required
          />

          <FormControl
            v-model="ssoClientId"
            label="Client ID / App ID"
            type="text"
            placeholder="e.g. 123456789.apps.googleusercontent.com"
            required
          />

          <FormControl
            v-model="ssoClientSecret"
            type="password"
            :label="ssoEditing ? 'Client Secret (leave blank to keep current)' : 'Client Secret'"
            placeholder="••••••••••••••••••••••••••••••••"
            :required="!ssoEditing"
          />

          <div v-if="ssoProvider" class="rounded-md border border-outline-gray-1 bg-surface-gray-1 p-3">
            <p class="text-xs text-ink-gray-5 font-medium mb-1">OAuth Authorized Redirect URI / Callback URL</p>
            <div class="flex items-center gap-2">
              <code class="text-xs font-mono text-ink-gray-8 bg-surface-white px-2 py-1 rounded border border-outline-gray-1 flex-1 break-all">
                /_/accounts/{{ ssoProvider }}/login/callback/
              </code>
              <Button size="sm" variant="outline" label="Copy path" @click="copyToClipboard(`/_/accounts/${ssoProvider}/login/callback/`)" />
            </div>
            <p class="text-p-xs text-ink-gray-4 mt-1.5">
              Copy this callback path and register it in your OAuth provider console (e.g. Google Cloud Console, GitHub OAuth App, Microsoft Entra ID).
            </p>
          </div>
        </div>
      </template>
      <template #actions="{ close }">
        <div class="flex justify-end gap-2 w-full">
          <Button label="Cancel" @click="close" />
          <Button
            variant="solid" theme="gray" :label="ssoEditing ? 'Update Provider' : 'Save Provider'"
            :loading="ssoSaving"
            :disabled="!ssoName.trim() || !ssoClientId.trim() || (!ssoEditing && !ssoClientSecret.trim())"
            @click="handleSaveSso(close)"
          />
        </div>
      </template>
    </Dialog>
  </div>
</template>
