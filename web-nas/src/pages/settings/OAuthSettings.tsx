// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, useCallback } from 'react'
import {
  CheckCircle2,
  XCircle,
  ExternalLink,
  RefreshCw,
} from 'lucide-react'
import {
  PageHeader,
  Card,
  Button,
  Input,
  Toggle,
  Badge,
  Spinner,
} from '../../components/ui'
import { api } from '../../api'
import type { OAuthConfig, OAuthProvider, OAuthDiscoveryResult } from '../../types'

type ProviderPreset = 'microsoft' | 'authentik' | 'keycloak' | 'google' | 'okta' | 'custom'

const PRESET_LABELS: Record<ProviderPreset, string> = {
  microsoft: 'Microsoft 365',
  authentik: 'Authentik',
  keycloak: 'Keycloak',
  google: 'Google Workspace',
  okta: 'Okta',
  custom: 'Custom OIDC',
}

const PRESET_DESCRIPTIONS: Record<ProviderPreset, string> = {
  microsoft: 'Azure AD / Entra ID',
  authentik: 'Open-source IdP',
  keycloak: 'Red Hat SSO',
  google: 'Google Cloud Identity',
  okta: 'Workforce identity',
  custom: 'Any OIDC provider',
}

export default function OAuthSettings() {
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Config form state
  const [enabled, setEnabled] = useState(false)
  const [providerName, setProviderName] = useState('')
  const [issuerUrl, setIssuerUrl] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [redirectUri, setRedirectUri] = useState('')
  const [scopes, setScopes] = useState('openid profile email')
  const [autoProvision, setAutoProvision] = useState(false)
  const [hasExistingSecret, setHasExistingSecret] = useState(false)

  // Provider presets
  const [providers, setProviders] = useState<OAuthProvider[]>([])
  const [selectedPreset, setSelectedPreset] = useState<ProviderPreset | null>(null)

  // Discovery test result
  const [discoveryResult, setDiscoveryResult] = useState<OAuthDiscoveryResult | null>(null)

  const fetchConfig = useCallback(async () => {
    try {
      const config: OAuthConfig = await api.getOauthConfig()
      setEnabled(config.enabled)
      setProviderName(config.provider_name)
      setIssuerUrl(config.issuer_url)
      setClientId(config.client_id)
      setRedirectUri(config.redirect_uri || guessRedirectUri())
      setScopes(config.scopes || 'openid profile email')
      setAutoProvision(config.auto_provision)
      setHasExistingSecret(config.has_client_secret)
    } catch {
      // Config not yet set -- use defaults
      setRedirectUri(guessRedirectUri())
    } finally {
      setLoading(false)
    }
  }, [])

  const fetchProviders = useCallback(async () => {
    try {
      const list = await api.getOauthProviders()
      setProviders(Array.isArray(list) ? list : [])
    } catch {
      // Providers endpoint may not be available
    }
  }, [])

  useEffect(() => {
    fetchConfig()
    fetchProviders()
  }, [fetchConfig, fetchProviders])

  function guessRedirectUri(): string {
    return `${window.location.origin}/api/v1/auth/oauth/callback`
  }

  function handlePresetSelect(presetId: ProviderPreset) {
    setSelectedPreset(presetId)
    const provider = providers.find((p) => p.id === presetId)
    if (provider) {
      setProviderName(provider.name)
      if (provider.issuer_template) {
        setIssuerUrl(provider.issuer_template)
      }
      if (provider.scopes) {
        setScopes(provider.scopes)
      }
    }
    if (!redirectUri) {
      setRedirectUri(guessRedirectUri())
    }
    setDiscoveryResult(null)
    setError(null)
    setSuccess(null)
  }

  async function handleSave() {
    setError(null)
    setSuccess(null)
    setSaving(true)

    try {
      await api.saveOauthConfig({
        enabled,
        provider_name: providerName,
        issuer_url: issuerUrl,
        client_id: clientId,
        client_secret: clientSecret || undefined,
        redirect_uri: redirectUri,
        scopes,
        auto_provision: autoProvision,
      })
      setSuccess('OIDC configuration saved.')
      if (clientSecret) {
        setHasExistingSecret(true)
        setClientSecret('')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save configuration')
    } finally {
      setSaving(false)
    }
  }

  async function handleTestDiscovery() {
    setError(null)
    setSuccess(null)
    setTesting(true)
    setDiscoveryResult(null)

    try {
      // Save the issuer URL first so the test endpoint can read it
      await api.saveOauthConfig({ issuer_url: issuerUrl })
      const result = await api.testOauthDiscovery()
      setDiscoveryResult(result)
      if (result.success) {
        setSuccess('OIDC discovery successful. All required endpoints found.')
      } else {
        setError(result.error || 'Discovery failed.')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Discovery test failed')
    } finally {
      setTesting(false)
    }
  }

  if (loading) return <Spinner label="Loading OIDC configuration..." />

  return (
    <div className="space-y-6">
      <PageHeader
        title="Single Sign-On (OIDC)"
        subtitle="Configure OIDC/OAuth2 authentication with an external identity provider"
        actions={
          <div className="flex items-center gap-3">
            <Toggle
              checked={enabled}
              onChange={setEnabled}
              label={enabled ? 'Enabled' : 'Disabled'}
            />
          </div>
        }
      />

      {/* Status */}
      {error && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 animate-fade-in">
          <div className="flex items-start gap-2">
            <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <p className="text-xs text-red-400">{error}</p>
          </div>
        </div>
      )}
      {success && (
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-4 animate-fade-in">
          <div className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <p className="text-xs text-emerald-400">{success}</p>
          </div>
        </div>
      )}

      {/* Provider presets */}
      <Card title="Identity Provider">
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          {(Object.keys(PRESET_LABELS) as ProviderPreset[]).map((id) => (
            <button
              key={id}
              type="button"
              onClick={() => handlePresetSelect(id)}
              className={`
                p-3 rounded-lg border text-left transition-all duration-200
                ${selectedPreset === id
                  ? 'border-sky-500/50 bg-sky-500/5'
                  : 'border-navy-800/50 bg-navy-800/20 hover:border-navy-700/50 hover:bg-navy-800/30'
                }
              `}
            >
              <p className={`text-sm font-medium ${selectedPreset === id ? 'text-sky-400' : 'text-gray-200'}`}>
                {PRESET_LABELS[id]}
              </p>
              <p className="text-[10px] text-navy-500 mt-0.5">{PRESET_DESCRIPTIONS[id]}</p>
            </button>
          ))}
        </div>
      </Card>

      {/* Configuration form */}
      <Card title="Configuration">
        <div className="space-y-4">
          <Input
            label="Provider Name"
            value={providerName}
            onChange={(e) => setProviderName(e.target.value)}
            placeholder="e.g. Microsoft 365, Authentik, Keycloak"
          />

          <Input
            label="Issuer URL"
            value={issuerUrl}
            onChange={(e) => setIssuerUrl(e.target.value)}
            placeholder="https://login.microsoftonline.com/{tenant}/v2.0"
            mono
          />

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Input
              label="Client ID"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              placeholder="Application / Client ID"
              mono
            />
            <div>
              <Input
                label="Client Secret"
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                placeholder={hasExistingSecret ? '(unchanged - enter new value to update)' : 'Client secret'}
                mono
              />
              {hasExistingSecret && !clientSecret && (
                <p className="text-[10px] text-emerald-500 mt-1">Secret is set. Leave blank to keep current value.</p>
              )}
            </div>
          </div>

          <Input
            label="Redirect URI"
            value={redirectUri}
            onChange={(e) => setRedirectUri(e.target.value)}
            placeholder="https://nas.local/api/v1/auth/oauth/callback"
            mono
          />
          <p className="text-[10px] text-navy-500 -mt-2">
            Register this URL as an allowed redirect URI in your identity provider.
          </p>

          <Input
            label="Scopes"
            value={scopes}
            onChange={(e) => setScopes(e.target.value)}
            placeholder="openid profile email"
            mono
          />

          <Toggle
            checked={autoProvision}
            onChange={setAutoProvision}
            label="Auto-provision users on first SSO login"
          />
          {autoProvision && (
            <p className="text-[10px] text-amber-400 -mt-2 pl-12">
              New users created via SSO will have the &quot;user&quot; role (not admin).
            </p>
          )}
        </div>
      </Card>

      {/* Test discovery */}
      <Card title="Test Discovery">
        <div className="space-y-4">
          <p className="text-xs text-navy-400">
            Fetch the OIDC discovery document from the issuer URL to verify connectivity
            and check that all required endpoints are available.
          </p>
          <Button
            size="sm"
            variant="secondary"
            onClick={handleTestDiscovery}
            loading={testing}
            disabled={!issuerUrl}
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1.5 inline" />
            Test Discovery
          </Button>

          {discoveryResult?.discovered && (
            <div className="p-4 bg-navy-800/30 rounded-lg space-y-2 font-mono text-xs">
              <div className="flex items-center gap-2">
                <Badge variant={discoveryResult.success ? 'success' : 'danger'}>
                  {discoveryResult.success ? 'Valid' : 'Incomplete'}
                </Badge>
              </div>
              <div className="space-y-1 mt-2">
                <p className="text-navy-400">
                  <span className="text-navy-500">issuer:</span>{' '}
                  <span className="text-gray-300">{discoveryResult.discovered.issuer}</span>
                </p>
                <p className="text-navy-400">
                  <span className="text-navy-500">authorization_endpoint:</span>{' '}
                  <span className="text-gray-300">{discoveryResult.discovered.authorization_endpoint}</span>
                </p>
                <p className="text-navy-400">
                  <span className="text-navy-500">token_endpoint:</span>{' '}
                  <span className="text-gray-300">{discoveryResult.discovered.token_endpoint}</span>
                </p>
                <p className="text-navy-400">
                  <span className="text-navy-500">jwks_uri:</span>{' '}
                  <span className="text-gray-300">{discoveryResult.discovered.jwks_uri}</span>
                </p>
                {discoveryResult.discovered.userinfo_endpoint && (
                  <p className="text-navy-400">
                    <span className="text-navy-500">userinfo_endpoint:</span>{' '}
                    <span className="text-gray-300">{discoveryResult.discovered.userinfo_endpoint}</span>
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Provider setup hints */}
      {selectedPreset && selectedPreset !== 'custom' && (
        <Card title="Setup Instructions">
          <div className="space-y-3 text-xs text-navy-400">
            {selectedPreset === 'microsoft' && (
              <>
                <p>1. Go to <span className="text-gray-300">Azure Portal &gt; Azure Active Directory &gt; App registrations</span></p>
                <p>2. Click <span className="text-gray-300">New registration</span></p>
                <p>3. Set the redirect URI to: <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">{redirectUri}</code></p>
                <p>4. Under <span className="text-gray-300">Certificates &amp; secrets</span>, create a new client secret</p>
                <p>5. Copy the <span className="text-gray-300">Application (client) ID</span> and <span className="text-gray-300">Directory (tenant) ID</span></p>
                <p>6. Replace <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">{'{tenant_id}'}</code> in the issuer URL with your tenant ID</p>
              </>
            )}
            {selectedPreset === 'authentik' && (
              <>
                <p>1. In Authentik, go to <span className="text-gray-300">Applications &gt; Providers</span></p>
                <p>2. Create a new <span className="text-gray-300">OAuth2/OpenID Provider</span></p>
                <p>3. Set the redirect URI to: <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">{redirectUri}</code></p>
                <p>4. Create an <span className="text-gray-300">Application</span> and link it to the provider</p>
                <p>5. Copy the Client ID and Client Secret from the provider settings</p>
                <p>6. The issuer URL follows the pattern: <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">https://auth.example.com/application/o/app-slug/</code></p>
              </>
            )}
            {selectedPreset === 'keycloak' && (
              <>
                <p>1. In Keycloak, select your realm and go to <span className="text-gray-300">Clients</span></p>
                <p>2. Click <span className="text-gray-300">Create client</span></p>
                <p>3. Set Client type to <span className="text-gray-300">OpenID Connect</span></p>
                <p>4. Set the Valid redirect URI to: <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">{redirectUri}</code></p>
                <p>5. Copy the Client ID and Client Secret from the client Credentials tab</p>
                <p>6. The issuer URL is: <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">{'https://{host}/realms/{realm}'}</code></p>
              </>
            )}
            {selectedPreset === 'google' && (
              <>
                <p>1. Go to <span className="text-gray-300">Google Cloud Console &gt; APIs &amp; Services &gt; Credentials</span></p>
                <p>2. Click <span className="text-gray-300">Create Credentials &gt; OAuth client ID</span></p>
                <p>3. Set application type to <span className="text-gray-300">Web application</span></p>
                <p>4. Add the redirect URI: <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">{redirectUri}</code></p>
                <p>5. The issuer URL for Google is always: <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">https://accounts.google.com</code></p>
              </>
            )}
            {selectedPreset === 'okta' && (
              <>
                <p>1. In the Okta admin console, go to <span className="text-gray-300">Applications &gt; Create App Integration</span></p>
                <p>2. Select <span className="text-gray-300">OIDC - OpenID Connect</span> and <span className="text-gray-300">Web Application</span></p>
                <p>3. Set the Sign-in redirect URI to: <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">{redirectUri}</code></p>
                <p>4. Copy the Client ID and Client Secret</p>
                <p>5. The issuer URL is: <code className="text-sky-400 bg-navy-800/50 px-1.5 py-0.5 rounded">{'https://{domain}/oauth2/default'}</code></p>
              </>
            )}
            <div className="pt-2">
              <a
                href={getProviderDocsUrl(selectedPreset)}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sky-400 hover:text-sky-300 transition-colors inline-flex items-center gap-1"
              >
                View documentation
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </Card>
      )}

      {/* Save button */}
      <div className="flex justify-end gap-3">
        <Button variant="secondary" size="sm" onClick={fetchConfig}>
          Reset
        </Button>
        <Button size="sm" onClick={handleSave} loading={saving}>
          Save Configuration
        </Button>
      </div>
    </div>
  )
}

function getProviderDocsUrl(preset: ProviderPreset): string {
  switch (preset) {
    case 'microsoft':
      return 'https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app'
    case 'authentik':
      return 'https://docs.goauthentik.io/docs/providers/oauth2/'
    case 'keycloak':
      return 'https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients'
    case 'google':
      return 'https://developers.google.com/identity/openid-connect/openid-connect'
    case 'okta':
      return 'https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/'
    default:
      return 'https://openid.net/developers/how-connect-works/'
  }
}
