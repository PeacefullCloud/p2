import { ref, computed } from 'vue'
import { useApi } from './api'

// ── Shared active bucket (not tied to a single component) ────────────────
const activeBucket = ref(null)
const buckets = ref([])

// ── Composable: bucket list ──────────────────────────────────────────────

export function useBuckets() {
  const { data, isFetching, error, execute } = useApi('/core/volume/', {
    refetch: true,
  }).json()

  // Normalize API response into frontend shape
  const list = computed(() => {
    const raw = data.value
    if (!raw) return []
    return raw.map(v => ({
      uuid: v.uuid,
      name: v.name,
      object_count: v.object_count || 0,
      space_used_bytes: v.space_used_bytes || 0,
      tags: v.tags || {},
      creationDate: v.tags?.created || '',
      region: v.tags?.region || 'us-east-1',
      versioning: v.tags?.versioning === 'true' || v.tags?.versioning === true,
      accessPolicy: v.tags?.access_policy || 'private',
      encryption: v.tags?.encryption || 'AES-256',
      corsRules: Array.isArray(v.tags?.['s3.p2.io/cors/rules'])
        ? v.tags['s3.p2.io/cors/rules']
        : [],
      permissions: v.permissions || [],
      canAdmin: (v.permissions || []).includes('admin'),
      canWrite: (v.permissions || []).includes('write'),
      canDelete: (v.permissions || []).includes('delete'),
    }))
  })

  // Keep shared buckets ref in sync
  const syncBuckets = () => { buckets.value = list.value }
  syncBuckets()
  // Watch for changes (use computed setter or manual sync)
  const originalExecute = execute
  const fetchAndSync = async () => {
    await originalExecute()
    syncBuckets()
  }

  // ── Create bucket ────────────────────────────────────────────────────
  const createBody = ref({ name: '', storage_uuid: null, tags: {} })
  const { execute: createExecute, isFetching: creating, error: createError } = useApi(
    '/core/volume/',
    { immediate: false },
  ).post(createBody).json()

  async function createBucket(payload) {
    const tags = {}
    if (payload.region) tags.region = payload.region
    if (payload.encryption) tags.encryption = payload.encryption
    if (payload.accessPolicy) tags.access_policy = payload.accessPolicy
    if (payload.versioning !== undefined) tags.versioning = String(payload.versioning)
    createBody.value = { name: payload.name, storage_uuid: payload.storage_uuid || null, tags }
    await createExecute()
    if (createError.value) throw createError.value
    await fetchAndSync()
    return data.value
  }

  // ── Delete bucket ────────────────────────────────────────────────────
  const deleting = ref(false)
  const deleteError = ref(null)

  async function deleteBucket(uuid) {
    deleting.value = true
    deleteError.value = null
    try {
      const token = localStorage.getItem('p2_token') || ''
      const resp = await fetch(`/api/v1/core/volume/${uuid}/`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}))
        throw new Error(body.detail || `HTTP ${resp.status}`)
      }
      if (activeBucket.value?.uuid === uuid) activeBucket.value = null
      await fetchAndSync()
    } catch (e) {
      deleteError.value = e
      throw e
    } finally {
      deleting.value = false
    }
  }

  // ── Update bucket settings ──────────────────────────────────────────
  const updating = ref(false)
  const updateError = ref(null)

  async function updateBucket(uuid, payload) {
    updating.value = true
    updateError.value = null
    try {
      const token = localStorage.getItem('p2_token') || ''
      const reqBody = {}
      if (payload.accessPolicy !== undefined) reqBody.access_policy = payload.accessPolicy
      if (payload.versioning !== undefined) reqBody.versioning = payload.versioning
      if (payload.encryption !== undefined) reqBody.encryption = payload.encryption
      if (payload.corsRules !== undefined) reqBody.cors_rules = payload.corsRules
      const resp = await fetch(`/api/v1/core/volume/${uuid}/`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(reqBody),
      })
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}))
        throw new Error(body.detail || `HTTP ${resp.status}`)
      }
      await fetchAndSync()
    } catch (e) {
      updateError.value = e
      throw e
    } finally {
      updating.value = false
    }
  }

  // ── Select bucket ────────────────────────────────────────────────────
  function selectBucket(bucket) {
    activeBucket.value = bucket
  }

  // ── Computed stats ───────────────────────────────────────────────────
  const bucketStats = computed(() => ({
    total: list.value.length,
    totalObjects: list.value.reduce((s, b) => s + (b.object_count || 0), 0),
    totalBytes: list.value.reduce((s, b) => s + (b.space_used_bytes || 0), 0),
  }))

  return {
    buckets: list,
    loading: isFetching,
    error,
    fetchBuckets: fetchAndSync,
    createBucket,
    creating,
    createError,
    deleteBucket,
    deleting,
    deleteError,
    updateBucket,
    updating,
    updateError,
    selectBucket,
    activeBucket,
    bucketStats,
  }
}

// Default singleton instance (for pages that don't need isolation)
let defaultInstance = null

export function useBucketsSingleton() {
  if (!defaultInstance) defaultInstance = useBuckets()
  return defaultInstance
}

export { activeBucket, buckets }
