import { useApi, getUser, saveTokens } from './api'
import { computed, ref, watch } from 'vue'

// ── Shared config ────────────────────────────────────────────────────────
const config = ref({
  s3_endpoint: '',
  storage_classes: [],
  encryption_options: [],
  region_options: [],
  version: '',
})
const apiKeys = ref([])
const users = ref([])
const policies = ref([])
const authPolicies = ref([])
const groups = ref([])
const ssoProviders = ref([])
const availableProviders = ref([])

// ── Composable: all settings ─────────────────────────────────────────────

export function useSettings() {
  const user = getUser()
  const isSuperuser = computed(() => !!user.value?.is_superuser)

  // ── System Config ────────────────────────────────────────────────────
  const { data: cfgData, isFetching: cfgLoading, execute: fetchCfg } = useApi(
    '/system/config/',
    { refetch: true },
  ).json()

  const cfg = computed(() => {
    if (cfgData.value) config.value = cfgData.value
    return config.value
  })

  // ── API Keys ──────────────────────────────────────────────────────────
  const { data: keysData, isFetching: keysLoading, execute: fetchKeys } = useApi(
    '/system/key/',
    { refetch: true },
  ).json()

  const keys = computed(() => {
    if (keysData.value) apiKeys.value = keysData.value
    return apiKeys.value
  })

  // Create
  const keyCreateBody = ref({})
  const { data: keyCreateData, execute: keyCreate, isFetching: keyCreating, error: keyCreateError } = useApi(
    '/system/key/',
    { immediate: false },
  ).post(keyCreateBody).json()

  async function createApiKey(payload) {
    keyCreateBody.value = payload
    await keyCreate()
    if (keyCreateError.value) throw keyCreateError.value
    await fetchKeys()
    return keyCreateData.value
  }

  // Delete
  const keyDeleting = ref(false)
  const keyDelError = ref(null)

  async function deleteApiKey(id) {
    keyDeleting.value = true
    keyDelError.value = null
    try {
      const token = localStorage.getItem('p2_token') || ''
      const resp = await fetch(`/api/v1/system/key/${id}/`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}))
        throw new Error(body.detail || `HTTP ${resp.status}`)
      }
      await fetchKeys()
    } catch (e) {
      keyDelError.value = e
      throw e
    } finally {
      keyDeleting.value = false
    }
  }

  // ── Users ──────────────────────────────────────────────────────────────
  const { data: usersData, isFetching: usersLoading, execute: fetchUsers } = useApi(
    '/system/user/',
    { immediate: false, refetch: true },
  ).json()

  const usersList = computed(() => {
    if (usersData.value) users.value = usersData.value
    return users.value
  })

  // Create
  const userCreateBody = ref({})
  const { execute: userCreate, isFetching: userCreating, error: userCreateError } = useApi(
    '/system/user/',
    { immediate: false },
  ).post(userCreateBody).json()

  async function createUser(payload) {
    userCreateBody.value = {
      username: payload.username,
      password: payload.password,
      email: payload.email,
      is_active: payload.is_active !== undefined ? payload.is_active : true,
      is_superuser: payload.is_superuser || false,
      groups: payload.groups || [],
    }
    await userCreate()
    if (userCreateError.value) throw userCreateError.value
    await fetchUsers()
  }

  async function updateUser(id, payload) {
    const token = localStorage.getItem('p2_token') || ''
    const resp = await fetch(`/api/v1/system/user/${id}/`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${resp.status}`)
    }
    await fetchUsers()
  }

  async function deleteUser(id) {
    const token = localStorage.getItem('p2_token') || ''
    const resp = await fetch(`/api/v1/system/user/${id}/`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${resp.status}`)
    }
    await fetchUsers()
  }

  // ── Policies ───────────────────────────────────────────────────────────
  const { data: policiesData, isFetching: policiesLoading, execute: fetchPolicies } = useApi(
    '/tier0/policy/',
    { immediate: false, refetch: true },
  ).json()

  const policiesList = computed(() => {
    if (policiesData.value) policies.value = policiesData.value
    return policies.value
  })

  // Create
  const policyCreateBody = ref({})
  const { execute: policyCreate, isFetching: policyCreating, error: policyCreateError } = useApi(
    '/tier0/policy/',
    { immediate: false },
  ).post(policyCreateBody).json()

  async function createPolicy(payload) {
    policyCreateBody.value = payload
    await policyCreate()
    if (policyCreateError.value) throw policyCreateError.value
    await fetchPolicies()
  }

  // Update
  const policyUpdateBody = ref({})
  const { execute: policyUpdate, isFetching: policyUpdating, error: policyUpdateError } = useApi(
    (args) => args ? `/tier0/policy/${args.id}/` : '/tier0/policy/_placeholder/',
    { immediate: false },
  ).put(policyUpdateBody).json()

  async function updatePolicy(id, payload) {
    policyUpdateBody.value = payload
    await policyUpdate({ id })
    if (policyUpdateError.value) throw policyUpdateError.value
    await fetchPolicies()
  }

  // Delete
  const policyDeleting = ref(false)
  const policyDelError = ref(null)

  async function deletePolicy(id) {
    policyDeleting.value = true
    policyDelError.value = null
    try {
      const token = localStorage.getItem('p2_token') || ''
      const resp = await fetch(`/api/v1/tier0/policy/${id}/`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}))
        throw new Error(body.detail || `HTTP ${resp.status}`)
      }
      await fetchPolicies()
    } catch (e) {
      policyDelError.value = e
      throw e
    } finally {
      policyDeleting.value = false
    }
  }

  // ── MFA (TOTP two-factor auth) ──────────────────────────────────────────
  const { data: mfaStatusData, isFetching: mfaStatusLoading, execute: fetchMfaStatus } = useApi(
    '/auth/mfa/status',
    { refetch: true },
  ).json()

  const mfaEnabled = computed(() => !!mfaStatusData.value?.enabled)

  const { execute: mfaSetupExecute, data: mfaSetupData, isFetching: mfaSettingUp, error: mfaSetupError } = useApi(
    '/auth/mfa/setup',
    { immediate: false },
  ).post().json()

  async function setupMfa() {
    await mfaSetupExecute()
    if (mfaSetupError.value) throw mfaSetupError.value
    return mfaSetupData.value // { secret, otpauth_url, qr_svg }
  }

  const mfaConfirmBody = ref({})
  const { execute: mfaConfirmExecute, data: mfaConfirmData, isFetching: mfaConfirming, error: mfaConfirmError } = useApi(
    '/auth/mfa/confirm',
    { immediate: false },
  ).post(mfaConfirmBody).json()

  async function confirmMfa(code) {
    mfaConfirmBody.value = { code }
    await mfaConfirmExecute()
    if (mfaConfirmError.value) throw mfaConfirmError.value
    await fetchMfaStatus()
    return mfaConfirmData.value // { recovery_codes }
  }

  const mfaDisableBody = ref({})
  const { execute: mfaDisableExecute, isFetching: mfaDisabling, error: mfaDisableError } = useApi(
    '/auth/mfa/disable',
    { immediate: false },
  ).post(mfaDisableBody).json()

  async function disableMfa(password) {
    mfaDisableBody.value = { password }
    await mfaDisableExecute()
    if (mfaDisableError.value) throw mfaDisableError.value
    await fetchMfaStatus()
  }

  // Self-service password change. The server revokes every other session and
  // returns a fresh token pair so this browser stays signed in.
  async function changeOwnPassword(currentPassword, newPassword) {
    const resp = await fetch('/api/v1/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('p2_token') || ''}`,
      },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    })
    const body = await resp.json().catch(() => ({}))
    if (!resp.ok) throw new Error(body.detail || `HTTP ${resp.status}`)
    saveTokens(body.access, body.refresh)
  }

  // ── Auth Policies ────────────────────────────────────────────────────────
  const { data: authPoliciesData, isFetching: authPoliciesLoading, execute: fetchAuthPolicies } = useApi(
    '/system/auth-policy/',
    { immediate: false, refetch: true },
  ).json()

  const authPoliciesList = computed(() => {
    if (authPoliciesData.value) authPolicies.value = authPoliciesData.value
    return authPolicies.value
  })

  async function createAuthPolicy(payload) {
    const token = localStorage.getItem('p2_token') || ''
    const resp = await fetch('/api/v1/system/auth-policy/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${resp.status}`)
    }
    await fetchAuthPolicies()
    return resp.json()
  }

  async function updateAuthPolicy(id, payload) {
    const token = localStorage.getItem('p2_token') || ''
    const resp = await fetch(`/api/v1/system/auth-policy/${id}/`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${resp.status}`)
    }
    await fetchAuthPolicies()
    return resp.json()
  }

  async function deleteAuthPolicy(id) {
    const token = localStorage.getItem('p2_token') || ''
    const resp = await fetch(`/api/v1/system/auth-policy/${id}/`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${resp.status}`)
    }
    await fetchAuthPolicies()
  }

  async function getAffectedCount(requirement, groupId) {
    const token = localStorage.getItem('p2_token') || ''
    const params = new URLSearchParams({ requirement })
    if (groupId) params.append('group_id', groupId)
    const resp = await fetch(`/api/v1/system/auth-policy/affected-count/?${params}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!resp.ok) return { count: 0 }
    return resp.json()
  }

  // ── Groups ───────────────────────────────────────────────────────────────
  const { data: groupsData, isFetching: groupsLoading, execute: fetchGroups } = useApi(
    '/system/auth-policy/groups/',
    { immediate: false, refetch: true },
  ).json()

  const groupsList = computed(() => {
    if (groupsData.value) groups.value = groupsData.value
    return groups.value
  })

  // ── SSO Providers ────────────────────────────────────────────────────────
  const { data: ssoData, isFetching: ssoProvidersLoading, execute: fetchSso } = useApi(
    '/system/sso-providers/',
    { immediate: false, refetch: true },
  ).json()

  const ssoList = computed(() => {
    if (ssoData.value) ssoProviders.value = ssoData.value
    return ssoProviders.value
  })

  const { data: availData, isFetching: availLoading, execute: fetchAvail } = useApi(
    '/system/sso-providers/available/',
    { immediate: false, refetch: true },
  ).json()

  const availList = computed(() => {
    if (availData.value) availableProviders.value = availData.value
    return availableProviders.value
  })

  // ── SSO sign-in rules (allowed domains, create-on-first-login) ──────────
  const ssoSettings = ref({ allowed_email_domains: '', allow_jit_signup: false })
  const ssoSettingsLoading = ref(false)

  async function fetchSsoSettings() {
    ssoSettingsLoading.value = true
    try {
      const resp = await fetch('/api/v1/system/sso-providers/settings/', {
        headers: { Authorization: `Bearer ${localStorage.getItem('p2_token') || ''}` },
      })
      if (resp.ok) ssoSettings.value = await resp.json()
    } finally {
      ssoSettingsLoading.value = false
    }
  }

  async function saveSsoSettings(payload) {
    const resp = await fetch('/api/v1/system/sso-providers/settings/', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('p2_token') || ''}`,
      },
      body: JSON.stringify(payload),
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${resp.status}`)
    }
    ssoSettings.value = await resp.json()
    return ssoSettings.value
  }

  // Auto-fetch superuser-only data only when user is a superuser
  watch(isSuperuser, (val) => {
    if (val) {
      fetchSsoSettings()
      fetchUsers()
      fetchPolicies()
      fetchAuthPolicies()
      fetchGroups()
      fetchSso()
      fetchAvail()
    }
  }, { immediate: true })

  async function createSsoProvider(payload) {
    const token = localStorage.getItem('p2_token') || ''
    const resp = await fetch('/api/v1/system/sso-providers/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${resp.status}`)
    }
    await fetchSso()
    return resp.json()
  }

  async function updateSsoProvider(id, payload) {
    const token = localStorage.getItem('p2_token') || ''
    const resp = await fetch(`/api/v1/system/sso-providers/${id}/`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${resp.status}`)
    }
    await fetchSso()
    return resp.json()
  }

  async function deleteSsoProvider(id) {
    const token = localStorage.getItem('p2_token') || ''
    const resp = await fetch(`/api/v1/system/sso-providers/${id}/`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    })
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}))
      throw new Error(body.detail || `HTTP ${resp.status}`)
    }
    await fetchSso()
  }

  return {
    // Config
    config: cfg,
    configLoading: cfgLoading,
    fetchConfig: fetchCfg,
    // API Keys
    apiKeys: keys,
    keysLoading,
    fetchApiKeys: fetchKeys,
    createApiKey,
    keyCreating,
    deleteApiKey,
    keyDeleting,
    // Users
    users: usersList,
    usersLoading,
    fetchUsers,
    createUser,
    userCreating,
    updateUser,
    deleteUser,
    // Policies
    policies: policiesList,
    policiesLoading,
    fetchPolicies,
    createPolicy,
    policyCreating,
    updatePolicy,
    policyUpdating,
    deletePolicy,
    policyDeleting,
    // MFA
    mfaEnabled,
    mfaStatusLoading,
    fetchMfaStatus,
    setupMfa,
    mfaSettingUp,
    confirmMfa,
    mfaConfirming,
    disableMfa,
    mfaDisabling,
    changeOwnPassword,
    // Auth Policies
    authPolicies: authPoliciesList,
    authPoliciesLoading,
    fetchAuthPolicies,
    createAuthPolicy,
    updateAuthPolicy,
    deleteAuthPolicy,
    getAffectedCount,
    // Groups
    groups: groupsList,
    groupsLoading,
    fetchGroups,
    // SSO Providers
    ssoProviders: ssoList,
    ssoProvidersLoading,
    fetchSsoProviders: fetchSso,
    availableProviders: availList,
    availLoading,
    fetchAvailableProviders: fetchAvail,
    createSsoProvider,
    updateSsoProvider,
    deleteSsoProvider,
    ssoSettings,
    ssoSettingsLoading,
    fetchSsoSettings,
    saveSsoSettings,
  }
}

// ── Default singleton ────────────────────────────────────────────────────
let defaultInstance = null

export function useSettingsSingleton() {
  if (!defaultInstance) defaultInstance = useSettings()
  return defaultInstance
}

export { config, apiKeys, users, policies, authPolicies, groups, ssoProviders, availableProviders }
