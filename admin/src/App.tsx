import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth, hasAdminRole } from './hooks/useAuth'
import { ToastProvider } from './components/ui/Toast'
import { ErrorBoundary } from './components/ErrorBoundary'
import { Layout } from './components/Layout'
import { Login } from './pages/Login'
import { OidcCallback } from './pages/OidcCallback'
import { Dashboard } from './pages/Dashboard'
import { Users } from './pages/Users'
import { Teams } from './pages/Teams'
import { Roles } from './pages/Roles'
import { PolicyStudio } from './pages/PolicyStudio'
import { AuditLog } from './pages/AuditLog'
import { Applications } from './pages/Applications'
import { IdentitySources } from './pages/IdentitySources'
import { ScimSources } from './pages/ScimSources'
import { SigningKeys } from './pages/SigningKeys'
import { Sessions } from './pages/Sessions'
import { IdentityControls } from './pages/IdentityControls'
import { RecoveryOperators } from './pages/RecoveryOperators'

function Protected({ children }: { children: React.ReactNode }) {
  const { token, user, logout } = useAuth()
  // Authenticated is not enough — the admin console requires an administrator role. A limited operator
  // (chat_user) holds a valid token but must never reach these surfaces. Bounce non-admins back to
  // login; clearing the session avoids a redirect loop with a valid-but-unauthorized token.
  if (!token || !user) return <Navigate to="/login" replace />
  if (!hasAdminRole(user)) {
    logout()
    return <Navigate to="/login" replace state={{ denied: true }} />
  }
  return <>{children}</>
}

function PageBoundary({ children }: { children: React.ReactNode }) {
  return <ErrorBoundary>{children}</ErrorBoundary>
}

function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/callback" element={<OidcCallback />} />
            <Route path="/recovery-operators/self" element={<RecoveryOperators selfOnly />} />
            <Route element={<Protected><Layout /></Protected>}>
              <Route index element={<PageBoundary><Dashboard /></PageBoundary>} />
              <Route path="users"    element={<PageBoundary><Users /></PageBoundary>} />
              <Route path="teams"    element={<PageBoundary><Teams /></PageBoundary>} />
              <Route path="applications" element={<PageBoundary><Applications /></PageBoundary>} />
              <Route path="identity-sources" element={<PageBoundary><IdentitySources /></PageBoundary>} />
              <Route path="scim-sources" element={<PageBoundary><ScimSources /></PageBoundary>} />
              <Route path="signing-keys" element={<PageBoundary><SigningKeys /></PageBoundary>} />
              <Route path="sessions" element={<PageBoundary><Sessions /></PageBoundary>} />
              <Route path="identity-controls" element={<PageBoundary><IdentityControls /></PageBoundary>} />
              <Route path="recovery-operators" element={<PageBoundary><RecoveryOperators /></PageBoundary>} />
              <Route path="roles"    element={<PageBoundary><Roles /></PageBoundary>} />
              <Route path="studio"   element={<PageBoundary><PolicyStudio /></PageBoundary>} />
              <Route path="audit"    element={<PageBoundary><AuditLog /></PageBoundary>} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  )
}

export default App
