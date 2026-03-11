require('dotenv').config()
const express = require('express')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')
const fs = require('fs')
const path = require('path')
const { PrismaClient } = require('@prisma/client')

const app = express()
const PORT = Number(process.env.PORT || 4000)
const NODE_ENV = process.env.NODE_ENV || 'development'
const IS_PROD = NODE_ENV === 'production'
const TRUST_PROXY = process.env.TRUST_PROXY === 'true'
const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean)

const ALLOW_ALL_ORIGINS = ALLOWED_ORIGINS.includes('*') || process.env.CORS_ORIGIN === 'ALLOW_ALL'
const SECRET = process.env.JWT_SECRET || 'dev-secret'
const DB_FILE = process.env.DATA_FILE
  ? path.resolve(process.env.DATA_FILE)
  : path.join(__dirname, '_store.json')
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend')
const MAX_BODY_SIZE = process.env.MAX_BODY_SIZE || '1mb'
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000)
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 300)
const STORAGE_ENGINE = process.env.STORAGE_ENGINE || 'json'
const prisma = STORAGE_ENGINE === 'prisma' ? new PrismaClient() : null

const EMAIL_HOST = process.env.EMAIL_HOST || process.env.SMTP_HOST || ''
const EMAIL_PORT = Number(process.env.EMAIL_PORT || process.env.SMTP_PORT || 587)
const EMAIL_SECURE = String(process.env.EMAIL_SECURE || process.env.SMTP_SECURE || 'false').toLowerCase() === 'true'
const EMAIL_USER = process.env.EMAIL_USER || process.env.SMTP_USER || ''
const EMAIL_PASS = process.env.EMAIL_PASS || process.env.SMTP_PASS || ''
const EMAIL_FROM = process.env.EMAIL_FROM || EMAIL_USER || ''
const EMAIL_REPLY_TO = process.env.EMAIL_REPLY_TO || EMAIL_FROM || ''
const EMAIL_ENABLED = Boolean(EMAIL_HOST && EMAIL_PORT && EMAIL_USER && EMAIL_PASS && EMAIL_FROM)
let mailer = null

const DEFAULT_JWT_SECRET = 'replace-with-a-long-random-secret'
if (IS_PROD && (SECRET === 'dev-secret' || SECRET === DEFAULT_JWT_SECRET || (SECRET || '').length < 32)) {
  console.error('FATAL: JWT_SECRET is not set to a strong value. Set JWT_SECRET in your environment and restart.')
  process.exit(1)
}

if (STORAGE_ENGINE === 'prisma' && !process.env.DATABASE_URL) {
  console.error('FATAL: STORAGE_ENGINE=prisma requires DATABASE_URL to be set.')
  process.exit(1)
}

if (IS_PROD && ALLOWED_ORIGINS.length === 0) {
  console.warn('WARNING: CORS_ORIGIN is empty in production; this will allow requests from any origin. Consider setting it to a strict list of domains.')
}

app.disable('x-powered-by')
app.set('trust proxy', TRUST_PROXY)

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
  if (IS_PROD) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  }
  next()
})

app.use(cors({
  origin: (origin, callback) => {
    if (ALLOW_ALL_ORIGINS) {
      return callback(null, true)
    }
    // Allow any origin when not restricted (empty list), or when wildcard is explicitly allowed
    // Also allow local development origins (localhost / 127.0.0.1) when not in production.
    const isLocalhost = origin && /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(origin)
    if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin) || (!IS_PROD && isLocalhost)) {
      return callback(null, true)
    }
    return callback(new Error('Not allowed by CORS'))
  },
  credentials: true
}))
app.use(express.json({ limit: MAX_BODY_SIZE }))

const rateWindows = new Map()
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) return next()
  const key = req.ip || req.socket.remoteAddress || 'unknown'
  const now = Date.now()
  const existing = rateWindows.get(key) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS }
  if (now > existing.resetAt) {
    existing.count = 0
    existing.resetAt = now + RATE_LIMIT_WINDOW_MS
  }
  existing.count += 1
  rateWindows.set(key, existing)
  res.setHeader('X-RateLimit-Limit', RATE_LIMIT_MAX)
  res.setHeader('X-RateLimit-Remaining', Math.max(0, RATE_LIMIT_MAX - existing.count))
  if (existing.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests. Try again later.' })
  }
  return next()
})

app.use((req, _res, next) => {
  req.requestId = `r-${Date.now()}-${Math.floor(Math.random() * 100000)}`
  next()
})

async function maintenanceGate(req, res, next) {
  if (!req.path.startsWith('/api/')) return next()
  const openPaths = [
    '/api/health',
    '/api/ready',
    '/api/public/institution-settings',
    '/api/system/maintenance',
    '/api/auth/login'
  ]
  if (openPaths.includes(req.path)) return next()

  const maintenance = getMaintenanceState()
  if (!maintenance.enabled) return next()

  const header = req.headers.authorization
  const token = header ? header.split(' ')[1] : null
  if (!token) {
    return res.status(503).json({ error: maintenance.message, maintenance: true, endsAt: maintenance.endsAt })
  }
  try {
    const payload = jwt.verify(token, SECRET)
    const user = await userFromPayload(payload)
    const role = normalizeRoleName(user?.effectiveRole || user?.role)
    if (role === 'admin' || role === 'super_admin') return next()
    return res.status(503).json({ error: maintenance.message, maintenance: true, endsAt: maintenance.endsAt })
  } catch (_error) {
    return res.status(503).json({ error: maintenance.message, maintenance: true, endsAt: maintenance.endsAt })
  }
}

app.use(maintenanceGate)

function defaultStore() {
  return {
    users: [],
    faculties: [],
    hierarchyDepartments: [],
    hierarchyPrograms: [],
    hierarchyCourses: [],
    academicYears: [],
    hierarchySemesters: [],
    students: [],
    // Pre-approved registry for account creation (used by verified registration flow)
    registrationStudents: [],
    registrationStaff: [],
    registrationLecturers: [],
    invoices: [],
    registrationApprovals: [],
    gradeSheets: [],
    gradeEntries: [],
    registrationPolicy: {
      maxCredits: 24,
      minCredits: 12,
      minGpa: 2.0,
      feeThresholdPercent: 0.5,
      approvalModel: 'advisor'
    },
    gradingPolicy: {
      catWeight: 0.3,
      examWeight: 0.7
    },
    departments: [],
    programs: [],
    semesters: [],
    courses: [],
    timetable: [],
    courseRegistrations: [],
    assignments: [],
    submissions: [],
    attendance: [],
    results: [],
    examSessions: [],
    examSchedules: [],
    examRooms: [],
    examInvigilators: [],
    examPapers: [],
    examMarks: [],
    examModerations: [],
    resultApprovals: [],
    materials: [],
    announcements: [],
    messages: [],
    notifications: [],
    userVerifications: [],
    registrationLogs: [],
    feeStructures: [],
    financeAccounts: [],
    payments: [],
    admissions: [],
    passwordResets: [],
    documents: [],
    academicCalendar: [],
    lmsIntegrations: [],
    hostelAllocations: [],
    libraryItems: [],
    clearanceRequests: [],
    alumniProfiles: [],
    activityLogs: [],
    accountProfiles: [],
    rbacRoles: {},
    userRoleAssignments: [],
    institutionSettings: null,
    institutionSettingsHistory: []
  }
}

function loadStore() {
  const base = defaultStore()
  const dataDir = path.dirname(DB_FILE)
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true })
  if (!fs.existsSync(DB_FILE)) return base
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))
    return { ...base, ...parsed }
  } catch (error) {
    console.error('Failed to parse store, rebuilding from defaults', error)
    return base
  }
}

let store = loadStore()

function saveStore() {
  const dataDir = path.dirname(DB_FILE)
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true })
  const tempFile = `${DB_FILE}.tmp`
  fs.writeFileSync(tempFile, JSON.stringify(store, null, 2))
  fs.renameSync(tempFile, DB_FILE)
}

function nextId(collectionName) {
  const collection = store[collectionName] || []
  return collection.reduce((max, item) => (item.id > max ? item.id : max), 0) + 1
}

function cleanHandle(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
}

function splitName(fullName) {
  const parts = String(fullName || '').trim().split(/\s+/).filter(Boolean)
  const first = parts[0] || 'user'
  const last = parts[parts.length - 1] || 'user'
  return { first, last }
}

function generateUsername(name, personNumber) {
  const { first, last } = splitName(name)
  const suffix = String(personNumber || '').replace(/\D/g, '').slice(-3)
  const base = `${cleanHandle(first).slice(0, 1)}${cleanHandle(last).slice(0, 18)}`
  return `${base}${suffix || ''}` || `user${Math.floor(Math.random() * 1000)}`
}

function generateTemporaryPassword(length = 12) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%*'
  let out = ''
  for (let i = 0; i < length; i += 1) {
    out += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return out
}

function ensureUniqueUsername(preferred, excludeUserId = null) {
  const normalized = cleanHandle(preferred) || `user${Date.now().toString().slice(-4)}`
  const taken = new Set((store.accountProfiles || [])
    .filter((p) => excludeUserId === null || Number(p.userId) !== Number(excludeUserId))
    .map((p) => String(p.username || '').toLowerCase()))
  if (!taken.has(normalized)) return normalized
  let n = 1
  while (taken.has(`${normalized}${n}`)) n += 1
  return `${normalized}${n}`
}

function accountProfileForUser(userId) {
  return (store.accountProfiles || []).find((p) => p.userId === Number(userId)) || null
}

function upsertAccountProfile(userId, updates = {}) {
  if (!Array.isArray(store.accountProfiles)) store.accountProfiles = []
  let profile = store.accountProfiles.find((p) => p.userId === Number(userId))
  if (!profile) {
    profile = {
      id: nextId('accountProfiles'),
      userId: Number(userId),
      username: '',
      personNumber: '',
      phone: '',
      programId: null,
      departmentId: null,
      mustChangePassword: false,
      createdAt: nowIso(),
      updatedAt: nowIso()
    }
    store.accountProfiles.push(profile)
  }
  Object.assign(profile, updates, { updatedAt: nowIso() })
  return profile
}

function cascadeDeleteUserDataJson(userId) {
  const id = Number(userId)
  const courseIds = store.courses.filter((c) => c.lecturerId === id).map((c) => c.id)
  const assignmentIds = store.assignments.filter((a) => a.createdBy === id || courseIds.includes(a.courseId)).map((a) => a.id)

  store.students = (store.students || []).filter((x) => x.userId !== id)
  store.courseRegistrations = (store.courseRegistrations || []).filter((x) => x.studentId !== id)
  store.attendance = (store.attendance || []).filter((x) => x.studentId !== id && x.markedBy !== id && x.markedById !== id)
  store.results = (store.results || []).filter((x) => x.studentId !== id)
  store.financeAccounts = (store.financeAccounts || []).filter((x) => x.studentId !== id)
  store.payments = (store.payments || []).filter((x) => x.studentId !== id)
  store.submissions = (store.submissions || []).filter((x) => x.studentId !== id && !assignmentIds.includes(x.assignmentId))
  store.assignments = (store.assignments || []).filter((x) => x.createdBy !== id && !courseIds.includes(x.courseId))
  store.materials = (store.materials || []).filter((x) => x.uploadedBy !== id)
  store.messages = (store.messages || []).filter((x) => x.fromUserId !== id && x.toUserId !== id)
  store.notifications = (store.notifications || []).filter((x) => x.toUserId !== id && x.sentBy !== id && x.sentById !== id)
  store.clearanceRequests = (store.clearanceRequests || []).filter((x) => x.studentId !== id && x.reviewedBy !== id && x.reviewedById !== id)
  store.hostelAllocations = (store.hostelAllocations || []).filter((x) => x.studentId !== id)
  store.alumniProfiles = (store.alumniProfiles || []).filter((x) => x.userId !== id)
  store.registrationApprovals = (store.registrationApprovals || []).filter((x) => x.approvedBy !== id)
  store.gradeSheets = (store.gradeSheets || []).filter((x) => x.lecturerId !== id && x.approvedBy !== id && x.rejectedBy !== id)
  store.admissions = (store.admissions || []).filter((x) => x.studentUserId !== id && x.createdById !== id)
  store.userRoleAssignments = (store.userRoleAssignments || []).filter((x) => x.userId !== id)
  store.accountProfiles = (store.accountProfiles || []).filter((x) => x.userId !== id)
}

function nowIso() {
  return new Date().toISOString()
}

const RBAC_ROLES = [
  'super_admin',
  'admin',
  'registrar',
  'finance_officer',
  'hod',
  'lecturer',
  'student',
  'non_teaching_staff',
  'librarian',
  'it_support',
  'admissions_officer',
  'alumni'
]

const DEFAULT_ROLE_PERMISSIONS = {
  super_admin: ['*'],
  admin: [
    'users.create', 'users.view', 'users.update', 'users.delete',
    'academic.manage', 'finance.view', 'grades.approve', 'reports.view',
    'institution.view', 'institution.edit', 'registration.approve', 'system.lock'
  ],
  registrar: [
    'users.view', 'admissions.manage', 'registration.approve', 'academic.manage',
    'reports.view', 'institution.view', 'institution.edit', 'grades.approve'
  ],
  finance_officer: [
    'finance.view', 'finance.manage', 'reports.view', 'users.view', 'institution.view'
  ],
  hod: [
    'academic.view', 'grades.approve', 'reports.view', 'users.view'
  ],
  lecturer: [
    'academic.view', 'grades.entry', 'attendance.manage', 'reports.view'
  ],
  student: [
    'self.view', 'registration.self', 'finance.self', 'results.self'
  ],
  non_teaching_staff: [
    'services.manage', 'reports.view', 'users.view'
  ],
  librarian: [
    'library.manage', 'library.view', 'reports.view'
  ],
  it_support: [
    'system.support', 'logs.view', 'users.view'
  ],
  admissions_officer: [
    'admissions.manage', 'registration.approve', 'reports.view'
  ],
  alumni: [
    'self.view', 'alumni.self'
  ]
}

function normalizeRoleName(role) {
  const raw = String(role || '').toLowerCase().trim()
  const map = {
    staff: 'non_teaching_staff',
    'non-teaching staff': 'non_teaching_staff',
    nonteachingstaff: 'non_teaching_staff',
    finance: 'finance_officer',
    financeofficer: 'finance_officer',
    superadmin: 'super_admin'
  }
  return map[raw] || raw || 'student'
}

function dbRoleForAccessRole(role) {
  const normalized = normalizeRoleName(role)
  if (['super_admin', 'admin', 'registrar', 'finance_officer', 'hod'].includes(normalized)) return 'admin'
  if (normalized === 'non_teaching_staff') return 'staff'
  if (normalized === 'alumni') return 'student'
  if (normalized === 'lecturer' || normalized === 'student') return normalized
  return 'student'
}

function ensureRbacSeed() {
  if (!store.rbacRoles || typeof store.rbacRoles !== 'object') store.rbacRoles = {}
  RBAC_ROLES.forEach((role) => {
    if (!Array.isArray(store.rbacRoles[role])) {
      store.rbacRoles[role] = [...(DEFAULT_ROLE_PERMISSIONS[role] || [])]
    }
  })
  if (!Array.isArray(store.userRoleAssignments)) store.userRoleAssignments = []
  const superAdmin = store.users.find((u) => String(u.email || '').toLowerCase() === 'stephemutiso19@gmail.com')
  if (superAdmin && !store.userRoleAssignments.find((a) => a.userId === superAdmin.id)) {
    store.userRoleAssignments.push({ userId: superAdmin.id, accessRole: 'super_admin', updatedAt: nowIso() })
  }
  saveStore()
}

function getAssignedAccessRole(userId) {
  const assignment = (store.userRoleAssignments || []).find((a) => a.userId === Number(userId))
  if (!assignment) return null
  return normalizeRoleName(assignment.accessRole)
}

function getEffectiveRole(user) {
  const assigned = getAssignedAccessRole(user?.id)
  if (assigned) return assigned
  return normalizeRoleName(user?.role || 'student')
}

function permissionsForRole(role) {
  const normalized = normalizeRoleName(role)
  return store.rbacRoles?.[normalized] || DEFAULT_ROLE_PERMISSIONS[normalized] || []
}

function hasPermission(user, permission) {
  const role = getEffectiveRole(user)
  const perms = permissionsForRole(role)
  return perms.includes('*') || perms.includes(permission)
}

function defaultInstitutionSettings() {
  return {
    id: 1,
    institutionName: 'Tech Hub University',
    shortName: 'TECH HUB',
    motto: 'Advancing Knowledge, Science, Innovation, and Digital Excellence',
    yearEstablished: '2026',
    registrationNumber: 'THU-REG-2026-001',
    email: 'info@techhub.edu',
    phone: '+254700000000',
    alternativePhone: '+254711000000',
    websiteUrl: 'https://techhub.edu',
    country: 'Kenya',
    countyState: 'Mombasa',
    cityTown: 'Mombasa',
    physicalAddress: 'Tech Hub Main Campus',
    poBox: '123',
    postalCode: '80100',
    primaryColor: '#1f3554',
    secondaryColor: '#d59835',
    mainLogo: '',
    favicon: '',
    officialSeal: '',
    registrationCountdownEnabled: true,
    registrationCountdownTarget: '2026-03-31T23:59:00',
    registrationCountdownLabel: 'Registration closes on March 31, 2026 - 23:59',
    registrationCountdownMessage: 'Complete semester registration before the deadline.',
    maintenanceMode: false,
    maintenanceMessage: 'Portal under maintenance. Please check again later.',
    maintenanceEndsAt: '',
    campuses: [
      { name: 'Main Campus', address: 'Mombasa', phone: '+254700000000' }
    ],
    updatedAt: nowIso()
  }
}

function getInstitutionSettings() {
  if (!store.institutionSettings || typeof store.institutionSettings !== 'object') {
    store.institutionSettings = defaultInstitutionSettings()
    saveStore()
  }
  if (!Array.isArray(store.institutionSettingsHistory)) {
    store.institutionSettingsHistory = []
    saveStore()
  }
  return store.institutionSettings
}

function getMaintenanceState() {
  const settings = getInstitutionSettings()
  return {
    enabled: Boolean(settings.maintenanceMode),
    message: settings.maintenanceMessage || 'Portal under maintenance. Please check again later.',
    endsAt: settings.maintenanceEndsAt || ''
  }
}

function canEditInstitutionSettings(user) {
  return hasPermission(user, 'institution.edit')
}

function ensureAcademicHierarchySeed() {
  if (!Array.isArray(store.faculties) || store.faculties.length === 0) {
    store.faculties = [
      { id: 1, name: 'Faculty of Engineering', code: 'ENG' },
      { id: 2, name: 'Faculty of Maritime', code: 'MRT' },
      { id: 3, name: 'Faculty of Business', code: 'BUS' }
    ]
  }
  if (!Array.isArray(store.hierarchyDepartments) || store.hierarchyDepartments.length === 0) {
    store.hierarchyDepartments = [
      { id: 1, name: 'Department of Computer Science', code: 'CS', facultyId: 1, hodName: 'Dr. Ada' },
      { id: 2, name: 'Department of Marine Engineering', code: 'ME', facultyId: 2, hodName: 'Eng. Khamis' }
    ]
  }
  if (!Array.isArray(store.hierarchyPrograms) || store.hierarchyPrograms.length === 0) {
    store.hierarchyPrograms = [
      { id: 1, name: 'BSc Computer Science', code: 'BSC-CS', departmentId: 1, durationYears: 4, awardType: 'Degree', mode: 'Full-time' },
      { id: 2, name: 'Diploma in Maritime Transport', code: 'DIP-MT', departmentId: 2, durationYears: 3, awardType: 'Diploma', mode: 'Full-time' }
    ]
  }
  if (!Array.isArray(store.hierarchyCourses) || store.hierarchyCourses.length === 0) {
    store.hierarchyCourses = [
      { id: 1, code: 'CSC101', title: 'Introduction to Programming', programId: 1, creditHours: 3, year: 1, semester: 1, lecturerAssigned: 'Dr. Ada' },
      { id: 2, code: 'MAR202', title: 'Navigation Systems', programId: 2, creditHours: 4, year: 2, semester: 2, lecturerAssigned: 'Capt. Otieno' }
    ]
  }
  if (!Array.isArray(store.academicYears) || store.academicYears.length === 0) {
    store.academicYears = [
      { id: 1, name: '2026/2027', isActive: true }
    ]
  }
  if (!Array.isArray(store.hierarchySemesters) || store.hierarchySemesters.length === 0) {
    store.hierarchySemesters = [
      { id: 1, academicYearId: 1, name: 'Semester 1', registrationOpen: '2026-01-01', registrationClose: '2026-01-31', gradesLocked: false, resultsPublished: false, attendanceLocked: false },
      { id: 2, academicYearId: 1, name: 'Semester 2', registrationOpen: '2026-08-01', registrationClose: '2026-08-31', gradesLocked: false, resultsPublished: false, attendanceLocked: false }
    ]
  }
  store.hierarchySemesters.forEach((s) => {
    if (s.gradesLocked === undefined) s.gradesLocked = false
    if (s.resultsPublished === undefined) s.resultsPublished = false
    if (s.attendanceLocked === undefined) s.attendanceLocked = false
  })
  saveStore()
}

function ensureAccountProfilesSeed() {
  if (!Array.isArray(store.accountProfiles)) store.accountProfiles = []
  const roleAssignmentById = new Map((store.userRoleAssignments || []).map((a) => [a.userId, a.accessRole]))
  store.users.forEach((user) => {
    const accessRole = normalizeRoleName(roleAssignmentById.get(user.id) || user.role)
    const existing = accountProfileForUser(user.id)
    const prefix = accessRole === 'student' ? 'STD' : 'STF'
    const defaultNumber = `${prefix}${String(user.id).padStart(4, '0')}`
    const username = existing?.username || ensureUniqueUsername(generateUsername(user.name, existing?.personNumber || defaultNumber))
    upsertAccountProfile(user.id, {
      username,
      personNumber: existing?.personNumber || defaultNumber,
      phone: existing?.phone || '',
      mustChangePassword: Boolean(existing?.mustChangePassword)
    })
  })
  saveStore()
}

function getActiveAcademicYear() {
  return store.academicYears.find((y) => y.isActive) || store.academicYears[0] || null
}

function getOpenSemester() {
  const today = new Date().toISOString().slice(0, 10)
  return store.hierarchySemesters.find((s) => s.registrationOpen <= today && today <= s.registrationClose) || null
}

function getCurrentSemesterForGrading() {
  return getOpenSemester() || store.hierarchySemesters[store.hierarchySemesters.length - 1] || null
}

function getProgramCodeById(programId) {
  return store.hierarchyPrograms.find((p) => p.id === Number(programId))?.code || 'GEN'
}

function nextStudentRegNo(programCode, year) {
  const prefix = `${String(programCode || 'GEN').toUpperCase()}/${year}/`
  const seq = store.students
    .map((s) => s.registrationNumber)
    .filter((r) => typeof r === 'string' && r.startsWith(prefix))
    .map((r) => Number(r.split('/').pop()))
    .filter((n) => Number.isFinite(n))
    .sort((a, b) => b - a)[0] || 0
  return `${prefix}${String(seq + 1).padStart(3, '0')}`
}

function ensureStudentProfileForUser(user) {
  let row = store.students.find((s) => s.userId === user.id)
  if (!row) {
    row = {
      id: nextId('students'),
      userId: user.id,
      registrationNumber: null,
      programId: null,
      academicYearId: getActiveAcademicYear()?.id || null,
      yearOfStudy: 1,
      status: 'active',
      gpa: 0,
      isSuspended: false,
      createdAt: nowIso()
    }
    store.students.push(row)
    saveStore()
  }
  return row
}

function currentGpaForStudent(studentUserId) {
  const data = buildStudentResults(studentUserId)
  return Number(data.cgpa || 0)
}

function evaluateRegistrationEligibility(studentUserId) {
  const profile = store.students.find((s) => s.userId === studentUserId)
  if (!profile) return { ok: false, reason: 'Student profile missing' }
  if (profile.isSuspended || profile.status === 'suspended') return { ok: false, reason: 'Academic suspension' }
  const semester = getOpenSemester()
  if (!semester) return { ok: false, reason: 'Registration period is closed' }
  const gpa = currentGpaForStudent(studentUserId)
  const policy = store.registrationPolicy || {}
  if (gpa > 0 && gpa < Number(policy.minGpa || 2.0)) return { ok: false, reason: `GPA below threshold (${policy.minGpa || 2.0})` }
  const account = ensureFinanceAccount(studentUserId)
  const totalBalance = Number(account.tuitionBalance || 0) + Number(account.upkeepBalance || 0)
  const paidEnough = totalBalance <= 0 || totalBalance <= 2000 * (1 - Number(policy.feeThresholdPercent || 0.5))
  if (!paidEnough) return { ok: false, reason: 'Fees unpaid below required threshold' }
  return { ok: true, semester, profile, gpa, policy }
}

function logActivity(userId, action, details) {
  if (STORAGE_ENGINE === 'prisma') {
    if (!prisma || !prisma.activityLog) return
    prisma.activityLog.create({
      data: { userId, action, details: details || {} }
    }).catch((error) => console.error('activity log error', error))
    return
  }
  store.activityLogs.push({
    id: nextId('activityLogs'),
    userId,
    action,
    details,
    createdAt: nowIso()
  })
  saveStore()
}

function roleToDb(role) {
  const map = { student: 'STUDENT', lecturer: 'LECTURER', staff: 'STAFF', admin: 'ADMIN' }
  const dbRole = dbRoleForAccessRole(role)
  return map[String(dbRole || '').toLowerCase()] || null
}

function roleFromDb(role) {
  return String(role || '').toLowerCase()
}

function paymentMethodToDb(method) {
  const map = { mpesa: 'MPESA', bank: 'BANK', card: 'CARD' }
  return map[String(method || '').toLowerCase()] || null
}

function paymentTargetToDb(target) {
  return String(target || '').toLowerCase() === 'upkeep' ? 'UPKEEP' : 'TUITION'
}

function normalizeUserRecord(user) {
  if (!user) return null
  const baseRole = STORAGE_ENGINE === 'prisma' ? roleFromDb(user.role) : user.role
  const effectiveRole = getEffectiveRole({ ...user, role: baseRole })
  const profile = accountProfileForUser(user.id) || {}
  return {
    ...user,
    role: baseRole,
    effectiveRole,
    permissions: permissionsForRole(effectiveRole),
    username: profile.username || null,
    personNumber: profile.personNumber || null,
    phone: profile.phone || null,
    mustChangePassword: Boolean(profile.mustChangePassword)
  }
}

function userPublicView(user) {
  const normalized = normalizeUserRecord(user)
  return {
    id: normalized.id,
    name: normalized.name,
    email: normalized.email,
    role: normalized.effectiveRole || normalizeRoleName(normalized.role),
    baseRole: normalizeRoleName(normalized.role),
    twoFactorEnabled: Boolean(normalized.twoFactorEnabled),
    username: normalized.username || null,
    personNumber: normalized.personNumber || null,
    phone: normalized.phone || null,
    mustChangePassword: Boolean(normalized.mustChangePassword)
  }
}

async function userFromPayload(payload) {
  if (STORAGE_ENGINE === 'prisma') {
    const user = await prisma.user.findUnique({ where: { id: Number(payload.sub) } })
    return normalizeUserRecord(user)
  }
  return normalizeUserRecord(store.users.find((u) => u.id === payload.sub))
}

function issueToken(user) {
  return jwt.sign({ sub: user.id, role: roleFromDb(user.role), accessRole: getEffectiveRole(user) }, SECRET, { expiresIn: '7d' })
}

async function auth(req, res, next) {
  const header = req.headers.authorization
  if (!header) return res.status(401).json({ error: 'Missing bearer token' })
  const token = header.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Missing bearer token' })

  try {
    const payload = jwt.verify(token, SECRET)
    const user = await userFromPayload(payload)
    if (!user) return res.status(401).json({ error: 'User not found' })
    req.user = user
    return next()
  } catch (_error) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

function requireRole(roles) {
  return (req, res, next) => {
    const role = normalizeRoleName(req.user.effectiveRole || req.user.role)
    if (role === 'super_admin') return next()
    if (!roles.includes(role)) return res.status(403).json({ error: 'Forbidden' })
    return next()
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!hasPermission(req.user, permission)) return res.status(403).json({ error: `Missing permission: ${permission}` })
    return next()
  }
}

function requireAnyPermission(permissions) {
  return (req, res, next) => {
    const ok = permissions.some((permission) => hasPermission(req.user, permission))
    if (!ok) return res.status(403).json({ error: `Missing one of permissions: ${permissions.join(', ')}` })
    return next()
  }
}

function canonicalKey(key) {
  return String(key || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function normalizeBulkRow(row, fieldMap) {
  const normalized = {}
  const map = {}
  Object.keys(fieldMap).forEach((field) => {
    map[canonicalKey(field)] = field
  })
  Object.entries(row || {}).forEach(([key, value]) => {
    const field = map[canonicalKey(key)]
    if (!field) return
    normalized[field] = value
  })
  return normalized
}

function castBulkValue(value, type) {
  if (type === 'number') {
    const num = Number(value)
    return Number.isFinite(num) ? num : 0
  }
  if (type === 'boolean') {
    if (typeof value === 'boolean') return value
    return String(value).toLowerCase() === 'true' || String(value) === '1'
  }
  return value !== undefined && value !== null ? String(value).trim() : ''
}

function bulkModuleConfigs() {
  return {
    faculties: { collection: 'faculties', fields: { name: 'string', code: 'string' }, required: ['name'], uniqueBy: ['code', 'name'] },
    departments: { collection: 'hierarchyDepartments', fields: { name: 'string', code: 'string', facultyId: 'number', hodName: 'string' }, required: ['name', 'code'], uniqueBy: ['code'] },
    programs: { collection: 'hierarchyPrograms', fields: { name: 'string', code: 'string', departmentId: 'number', durationYears: 'number', awardType: 'string', mode: 'string' }, required: ['name', 'code'], uniqueBy: ['code'] },
    courses: { collection: 'hierarchyCourses', fields: { code: 'string', title: 'string', programId: 'number', creditHours: 'number', year: 'number', semester: 'number', lecturerAssigned: 'string' }, required: ['code', 'title'], uniqueBy: ['code'] },
    'academic-years': { collection: 'academicYears', fields: { name: 'string', isActive: 'boolean' }, required: ['name'], uniqueBy: ['name'] },
    yearsetup: { collection: 'hierarchySemesters', fields: { academicYearId: 'number', name: 'string', registrationOpen: 'string', registrationClose: 'string', gradesLocked: 'boolean', resultsPublished: 'boolean', attendanceLocked: 'boolean' }, required: ['academicYearId', 'name'] },
    admissions: { collection: 'admissions', fields: { name: 'string', email: 'string', phone: 'string', programCode: 'string', intake: 'string', status: 'string', registrationNumber: 'string' }, required: ['name', 'email'], uniqueBy: ['email'] },
    'fee-structures': { collection: 'feeStructures', fields: { level: 'string', tuitionPerSemester: 'number', upkeepPerSemester: 'number', currency: 'string' }, required: ['level'], uniqueBy: ['level'] },
    'exam-sessions': { collection: 'examSessions', fields: { academicYear: 'string', semester: 'string', examType: 'string', startDate: 'string', endDate: 'string', status: 'string' }, required: ['academicYear', 'semester', 'examType', 'startDate', 'endDate'] },
    'exam-schedules': { collection: 'examSchedules', fields: { sessionId: 'number', courseId: 'number', examDate: 'string', examTime: 'string', examRoom: 'string', invigilator: 'string', published: 'boolean' }, required: ['sessionId', 'courseId', 'examDate', 'examTime', 'examRoom'] },
    'exam-papers': { collection: 'examPapers', fields: { courseId: 'number', title: 'string', type: 'string', durationMinutes: 'number', totalMarks: 'number', fileUrl: 'string', createdBy: 'number' }, required: ['courseId', 'title', 'type'] },
    'exam-marks': { collection: 'examMarks', fields: { studentId: 'number', courseId: 'number', catMarks: 'number', assignmentMarks: 'number', examMarks: 'number', status: 'string', sessionId: 'number', submittedBy: 'number' }, required: ['studentId', 'courseId'] },
    'exam-moderation': { collection: 'examModerations', fields: { courseId: 'number', courseCode: 'string', lecturerId: 'number', status: 'string', notes: 'string' } },
    'exam-approvals': { collection: 'resultApprovals', fields: { courseId: 'number', courseCode: 'string', sessionId: 'number', status: 'string' } },
    'registrations-students': { collection: 'registrationStudents', fields: { regNumber: 'string', name: 'string', program: 'string', email: 'string', dob: 'string' }, required: ['regNumber', 'name'], uniqueBy: ['regNumber'] },
    'registrations-lecturers': { collection: 'registrationLecturers', fields: { regNumber: 'string', name: 'string', department: 'string', email: 'string' }, required: ['regNumber', 'name'], uniqueBy: ['regNumber'] },
    'registrations-staff': { collection: 'registrationStaff', fields: { regNumber: 'string', name: 'string', department: 'string', position: 'string', email: 'string' }, required: ['regNumber', 'name'], uniqueBy: ['regNumber'] },
    registrationApprovals: { collection: 'registrationApprovals', fields: { userId: 'number', status: 'string' } },
    users: { collection: 'users', fields: { name: 'string', email: 'string', role: 'string', password: 'string', personNumber: 'string', phone: 'string' }, required: ['name', 'email'], uniqueBy: ['email'] }
  }
}

function ensureFinanceAccount(studentId) {
  let account = store.financeAccounts.find((item) => item.studentId === studentId)
  if (!account) {
    account = {
      id: nextId('financeAccounts'),
      studentId,
      tuitionBalance: 1200,
      upkeepBalance: 450,
      updatedAt: nowIso()
    }
    store.financeAccounts.push(account)
    saveStore()
  }
  return account
}

function pointsForGrade(grade) {
  const map = { A: 4, B: 3, C: 2, D: 1, F: 0 }
  return map[grade] ?? 0
}

function gradeFromScore(score) {
  const s = Number(score || 0)
  if (s >= 70) return 'A'
  if (s >= 60) return 'B'
  if (s >= 50) return 'C'
  if (s >= 40) return 'D'
  return 'F'
}

function computeFinalMark(catMarks, examMarks) {
  const gp = store.gradingPolicy || { catWeight: 0.3, examWeight: 0.7 }
  const cat = Number(catMarks || 0)
  const exam = Number(examMarks || 0)
  const finalScore = Number((cat * Number(gp.catWeight || 0.3) + exam * Number(gp.examWeight || 0.7)).toFixed(2))
  return { finalScore, letter: gradeFromScore(finalScore) }
}

function computeExamTotals(catMarks, assignmentMarks, examMarks) {
  const catTotal = Number(catMarks || 0) + Number(assignmentMarks || 0)
  const result = computeFinalMark(catTotal, examMarks)
  return { totalMarks: result.finalScore, grade: result.letter }
}

function buildStudentResults(studentId) {
  const rows = store.results.filter((r) => {
    if (r.studentId !== studentId) return false
    if (r.approved !== true) return false
    if (r.semesterId) {
      const sem = store.hierarchySemesters.find((s) => s.id === Number(r.semesterId))
      if (sem && sem.resultsPublished !== true) return false
    }
    return true
  })
  const withCourse = rows
    .map((row) => {
      const course = store.courses.find((c) => c.id === row.courseId)
      return {
        ...row,
        courseCode: course?.code || 'N/A',
        courseTitle: course?.title || 'Unknown Course',
        credits: course?.credits || 0,
        gradePoints: (course?.credits || 0) * pointsForGrade(row.grade)
      }
    })

  const totalCredits = withCourse.reduce((sum, row) => sum + row.credits, 0)
  const totalPoints = withCourse.reduce((sum, row) => sum + row.gradePoints, 0)
  const cgpa = totalCredits ? Number((totalPoints / totalCredits).toFixed(2)) : 0

  return { rows: withCourse, totalCredits, totalPoints, cgpa }
}

async function ensureFinanceAccountData(studentId) {
  if (STORAGE_ENGINE !== 'prisma') return ensureFinanceAccount(studentId)

  const account = await prisma.financeAccount.upsert({
    where: { studentId },
    update: {},
    create: {
      studentId,
      tuitionBalance: 1200,
      upkeepBalance: 450
    }
  })
  return account
}

async function latestSemesterData() {
  if (STORAGE_ENGINE !== 'prisma') return store.semesters[store.semesters.length - 1] || null
  return prisma.semester.findFirst({ orderBy: { startDate: 'desc' } })
}

async function buildStudentResultsData(studentId) {
  if (STORAGE_ENGINE !== 'prisma') return buildStudentResults(studentId)

  const rows = await prisma.result.findMany({
    where: { studentId },
    include: { course: true },
    orderBy: { createdAt: 'desc' }
  })

  const withCourse = rows.map((row) => ({
    ...row,
    courseCode: row.course?.code || 'N/A',
    courseTitle: row.course?.title || 'Unknown Course',
    credits: row.course?.credits || 0,
    gradePoints: (row.course?.credits || 0) * pointsForGrade(row.grade)
  }))

  const totalCredits = withCourse.reduce((sum, row) => sum + row.credits, 0)
  const totalPoints = withCourse.reduce((sum, row) => sum + row.gradePoints, 0)
  const cgpa = totalCredits ? Number((totalPoints / totalCredits).toFixed(2)) : 0

  return { rows: withCourse, totalCredits, totalPoints, cgpa }
}

function seedData() {
  const seedUsers = [
    { email: 'stephemutiso19@gmail.com', name: 'Super Admin', role: 'admin', password: '2006@shawn_M' },
    { email: 'lecturer@example.com', name: 'Dr. Ada', role: 'lecturer', password: 'lecturerpass' },
    { email: 'student@example.com', name: 'Student One', role: 'student', password: 'studentpass' }
  ]
  seedUsers.forEach((seed) => {
    let user = store.users.find((u) => u.email === seed.email)
    if (!user) {
      user = {
        id: nextId('users'),
        email: seed.email,
        name: seed.name,
        password: bcrypt.hashSync(seed.password, 10),
        role: seed.role,
        twoFactorEnabled: false
      }
      store.users.push(user)
      return
    }
    if (!user.name) user.name = seed.name
    if (!user.role) user.role = seed.role
    if (user.twoFactorEnabled === undefined) user.twoFactorEnabled = false
    const defaultNumber = seed.role === 'student' ? `STD${String(user.id).padStart(4, '0')}` : `STF${String(user.id).padStart(4, '0')}`
    const username = ensureUniqueUsername(generateUsername(user.name, defaultNumber))
    upsertAccountProfile(user.id, {
      username,
      personNumber: defaultNumber,
      phone: '',
      mustChangePassword: false
    })
  })

  // Seed sample registry records which are used to verify registration before account creation
  if (!store.registrationStudents.find((r) => r.regNumber === 'CS2024-001')) {
    store.registrationStudents.push({
      id: nextId('registrationStudents'),
      regNumber: 'CS2024-001',
      name: 'John Doe',
      program: 'Computer Science',
      email: 'johndoe@email.com',
      dob: '2004-03-10'
    })
  }
  if (!store.registrationStaff.find((r) => r.regNumber === 'STF2024-001')) {
    store.registrationStaff.push({
      id: nextId('registrationStaff'),
      regNumber: 'STF2024-001',
      name: 'Mary Admin',
      department: 'Operations',
      position: 'Registrar',
      email: 'mary.admin@techhub.edu'
    })
  }
  if (!store.registrationLecturers.find((r) => r.regNumber === 'LCT2024-001')) {
    store.registrationLecturers.push({
      id: nextId('registrationLecturers'),
      regNumber: 'LCT2024-001',
      name: 'Dr. Ada Lovelace',
      department: 'Computer Science',
      email: 'ada.lovelace@techhub.edu'
    })
  }

  const csDepartment = store.departments.find((d) => d.code === 'CS')
  if (!csDepartment) {
    store.departments.push({ id: nextId('departments'), name: 'Computer Science', code: 'CS' })
  }

  const program = store.programs.find((p) => p.code === 'BSC-CS')
  if (!program) {
    const dept = store.departments.find((d) => d.code === 'CS')
    store.programs.push({
      id: nextId('programs'),
      name: 'BSc Computer Science',
      code: 'BSC-CS',
      departmentId: dept.id
    })
  }

  if (!store.semesters.find((s) => s.code === '2026-S1')) {
    store.semesters.push({
      id: nextId('semesters'),
      name: 'Semester 1 2026',
      code: '2026-S1',
      startDate: '2026-01-12',
      endDate: '2026-05-08'
    })
  }

  if (!store.courses.find((c) => c.code === 'CS101')) {
    const semester = store.semesters[0]
    const lecturer = store.users.find((u) => u.role === 'lecturer')
    store.courses.push({
      id: nextId('courses'),
      code: 'CS101',
      title: 'Intro to Computer Science',
      credits: 3,
      lecturerId: lecturer.id,
      semesterId: semester.id,
      departmentId: store.departments[0].id
    })
  }
  const lecturer = store.users.find((u) => u.role === 'lecturer' || u.role === 'staff')
  const student = store.users.find((u) => u.role === 'student')
  store.courses.forEach((course) => {
    if (!course.credits) course.credits = 3
    if (!course.semesterId) course.semesterId = store.semesters[0]?.id || null
    if (!course.departmentId) course.departmentId = store.departments[0]?.id || null
    if (!course.lecturerId && lecturer) course.lecturerId = lecturer.id
  })

  if (store.timetable.length === 0) {
    const course = store.courses[0]
    store.timetable.push({
      id: nextId('timetable'),
      courseId: course.id,
      day: 'Monday',
      startTime: '09:00',
      endTime: '11:00',
      venue: 'Lab A'
    })
  }

  if (store.assignments.length === 0) {
    const course = store.courses[0]
    store.assignments.push({
      id: nextId('assignments'),
      courseId: course.id,
      title: 'Assignment 1',
      description: 'Write a short algorithm analysis.',
      dueDate: '2026-03-15',
      createdBy: lecturer?.id || store.users[0]?.id
    })
  }

  if (!Array.isArray(store.examSessions)) store.examSessions = []
  if (!Array.isArray(store.examSchedules)) store.examSchedules = []
  if (!Array.isArray(store.examRooms)) store.examRooms = []
  if (!Array.isArray(store.examInvigilators)) store.examInvigilators = []
  if (!Array.isArray(store.examPapers)) store.examPapers = []
  if (!Array.isArray(store.examMarks)) store.examMarks = []
  if (!Array.isArray(store.examModerations)) store.examModerations = []
  if (!Array.isArray(store.resultApprovals)) store.resultApprovals = []

  if (store.examSessions.length === 0) {
    store.examSessions.push({
      id: nextId('examSessions'),
      academicYear: '2026/2027',
      semester: 'Semester 1',
      examType: 'Final Exam',
      startDate: '2026-04-20',
      endDate: '2026-05-02',
      status: 'scheduled'
    })
  }
  if (store.examRooms.length === 0) {
    store.examRooms.push({ id: nextId('examRooms'), name: 'Main Hall', capacity: 120 })
  }
  if (store.examInvigilators.length === 0) {
    store.examInvigilators.push({ id: nextId('examInvigilators'), name: 'Mr. Kamau', email: 'kamau@techhub.edu', phone: '+254700000001' })
  }
  if (store.examSchedules.length === 0 && store.courses[0]) {
    const session = store.examSessions[0]
    const course = store.courses[0]
    store.examSchedules.push({
      id: nextId('examSchedules'),
      sessionId: session.id,
      courseId: course.id,
      courseCode: course.code,
      courseTitle: course.title,
      examDate: '2026-04-22',
      examTime: '09:00',
      examRoom: store.examRooms[0]?.name || 'Main Hall',
      invigilator: store.examInvigilators[0]?.name || 'Invigilator',
      published: true
    })
  }
  if (store.examPapers.length === 0 && store.courses[0]) {
    const course = store.courses[0]
    store.examPapers.push({
      id: nextId('examPapers'),
      courseId: course.id,
      courseCode: course.code,
      title: 'Final Exam Paper',
      type: 'Final Exam',
      durationMinutes: 120,
      totalMarks: 100,
      fileUrl: 'https://portal.techhub.edu/exams/cs101-final.pdf',
      createdBy: lecturer?.id || store.users[0]?.id
    })
  }
  if (store.examMarks.length === 0 && student && store.courses[0]) {
    const course = store.courses[0]
    const total = computeFinalMark(24 + 6, 60)
    store.examMarks.push({
      id: nextId('examMarks'),
      studentId: student.id,
      courseId: course.id,
      catMarks: 24,
      assignmentMarks: 6,
      examMarks: 60,
      totalMarks: total.finalScore,
      grade: total.letter,
      status: 'submitted',
      sessionId: store.examSessions[0]?.id || null,
      submittedBy: lecturer?.id || store.users[0]?.id,
      createdAt: nowIso()
    })
  }
  if (store.examModerations.length === 0 && store.courses[0]) {
    const course = store.courses[0]
    store.examModerations.push({
      id: nextId('examModerations'),
      courseId: course.id,
      courseCode: course.code,
      lecturerId: lecturer?.id || store.users[0]?.id,
      status: 'pending',
      notes: 'Awaiting moderation',
      reviewedBy: null,
      reviewedAt: null
    })
  }
  if (store.resultApprovals.length === 0 && store.courses[0]) {
    const course = store.courses[0]
    store.resultApprovals.push({
      id: nextId('resultApprovals'),
      courseId: course.id,
      courseCode: course.code,
      sessionId: store.examSessions[0]?.id || null,
      status: 'pending',
      approvedBy: null,
      approvedAt: null,
      releasedAt: null
    })
  }

  if (store.feeStructures.length === 0) {
    store.feeStructures.push({
      id: nextId('feeStructures'),
      level: 'Undergraduate',
      tuitionPerSemester: 1200,
      upkeepPerSemester: 450,
      currency: 'KES'
    })
  }

  if (store.libraryItems.length === 0) {
    store.libraryItems.push({
      id: nextId('libraryItems'),
      title: 'Data Structures Handbook',
      author: 'S. Wanjiku',
      available: true
    })
  }

  if (store.academicCalendar.length === 0) {
    store.academicCalendar.push({
      id: nextId('academicCalendar'),
      title: 'Semester Opening',
      date: '2026-01-12',
      type: 'academic'
    })
    store.academicCalendar.push({
      id: nextId('academicCalendar'),
      title: 'CAT Week',
      date: '2026-03-20',
      type: 'exam'
    })
    store.academicCalendar.push({
      id: nextId('academicCalendar'),
      title: 'Final Exams',
      date: '2026-05-01',
      type: 'exam'
    })
  }

  if (store.lmsIntegrations.length === 0) {
    store.lmsIntegrations.push({
      id: nextId('lmsIntegrations'),
      provider: 'Moodle',
      enabled: true,
      url: 'https://moodle.techhub.edu',
      linkedAt: nowIso()
    })
    store.lmsIntegrations.push({
      id: nextId('lmsIntegrations'),
      provider: 'Google Classroom',
      enabled: false,
      url: 'https://classroom.google.com',
      linkedAt: nowIso()
    })
  }

  const course = store.courses[0]
  if (student && course && !store.courseRegistrations.find((r) => r.studentId === student.id && r.courseId === course.id)) {
    store.courseRegistrations.push({
      id: nextId('courseRegistrations'),
      studentId: student.id,
      courseId: course.id,
      status: 'registered',
      createdAt: nowIso()
    })
  }

  if (student && course && !store.results.find((r) => r.studentId === student.id && r.courseId === course.id)) {
    store.results.push({
      id: nextId('results'),
      studentId: student.id,
      courseId: course.id,
      score: 78,
      grade: 'B',
      semesterCode: '2026-S1',
      approved: true
    })
  }

  if (student && course && !store.attendance.find((a) => a.studentId === student.id && a.courseId === course.id)) {
    store.attendance.push({
      id: nextId('attendance'),
      studentId: student.id,
      courseId: course.id,
      date: '2026-02-10',
      present: true,
      markedBy: lecturer?.id || store.users[0]?.id
    })
  }

  if (student) ensureFinanceAccount(student.id)
  if (student) {
    const profile = ensureStudentProfileForUser(student)
    if (!profile.registrationNumber) {
      const activeYear = getActiveAcademicYear()
      const year = activeYear?.name?.split('/')[0] || String(new Date().getFullYear())
      profile.registrationNumber = nextStudentRegNo('BSC-CS', year)
      profile.programId = 1
      profile.academicYearId = activeYear?.id || null
      profile.yearOfStudy = 1
      profile.status = 'active'
      saveStore()
    }
  }

  if (student && !store.alumniProfiles.find((a) => a.email === student.email)) {
    store.alumniProfiles.push({
      id: nextId('alumniProfiles'),
      userId: student.id,
      name: student.name,
      email: student.email,
      graduationYear: 2029,
      employmentStatus: 'in-progress'
    })
  }
  saveStore()
}

if (STORAGE_ENGINE !== 'prisma') {
  seedData()
}
ensureRbacSeed()
ensureAcademicHierarchySeed()
ensureAccountProfilesSeed()

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, timestamp: nowIso() })
})

app.get('/api/ready', (_req, res) => {
  const dataDirExists = fs.existsSync(path.dirname(DB_FILE))
  res.json({ ok: dataDirExists, dataFile: DB_FILE, env: NODE_ENV, timestamp: nowIso() })
})

app.get('/api/system/maintenance', (_req, res) => {
  res.json(getMaintenanceState())
})

app.get('/api/public/institution-settings', (_req, res) => {
  const settings = getInstitutionSettings()
  res.json(settings)
})

app.get('/api/admin/institution-settings', auth, requirePermission('institution.view'), (req, res) => {
  const settings = getInstitutionSettings()
  res.json({
    ...settings,
    canEdit: hasPermission(req.user, 'institution.edit'),
    historyCount: store.institutionSettingsHistory.length
  })
})

app.get('/api/admin/institution-settings/history', auth, requirePermission('institution.view'), (_req, res) => {
  const history = Array.isArray(store.institutionSettingsHistory) ? store.institutionSettingsHistory : []
  res.json(history.slice().reverse())
})

app.put('/api/admin/institution-settings', auth, requirePermission('institution.edit'), (req, res) => {

  const current = getInstitutionSettings()
  const allowed = [
    'institutionName', 'shortName', 'motto', 'yearEstablished', 'registrationNumber',
    'email', 'phone', 'alternativePhone', 'websiteUrl',
    'country', 'countyState', 'cityTown', 'physicalAddress', 'poBox', 'postalCode',
    'primaryColor', 'secondaryColor',
    'mainLogo', 'favicon', 'officialSeal',
    'campuses',
    'registrationCountdownEnabled', 'registrationCountdownTarget', 'registrationCountdownLabel', 'registrationCountdownMessage',
    'maintenanceMode', 'maintenanceMessage', 'maintenanceEndsAt'
  ]

  const version = {
    version: (store.institutionSettingsHistory[store.institutionSettingsHistory.length - 1]?.version || 0) + 1,
    updatedAt: nowIso(),
    updatedById: req.user.id,
    updatedByName: req.user.name,
    snapshot: current
  }
  store.institutionSettingsHistory.push(version)

  const next = { ...current }
  allowed.forEach((key) => {
    if (req.body[key] !== undefined) next[key] = req.body[key]
  })
  next.updatedAt = nowIso()
  store.institutionSettings = next
  saveStore()
  logActivity(req.user.id, 'admin.institution-settings.update', { version: version.version })
  res.json({ ...next, canEdit: true, historyCount: store.institutionSettingsHistory.length })
})

app.post('/api/admin/institution-settings/restore', auth, requirePermission('institution.edit'), (req, res) => {
  const versionNo = Number(req.body.version)
  const history = Array.isArray(store.institutionSettingsHistory) ? store.institutionSettingsHistory : []
  const chosen = Number.isFinite(versionNo)
    ? history.find((h) => h.version === versionNo)
    : history[history.length - 1]
  if (!chosen) return res.status(404).json({ error: 'No history version found to restore.' })
  store.institutionSettings = { ...chosen.snapshot, updatedAt: nowIso() }
  saveStore()
  logActivity(req.user.id, 'admin.institution-settings.restore', { version: chosen.version })
  res.json({ ...store.institutionSettings, canEdit: true, restoredVersion: chosen.version })
})

app.post('/api/admin/institution-settings/restore-default', auth, requirePermission('institution.edit'), (req, res) => {
  store.institutionSettings = defaultInstitutionSettings()
  store.institutionSettings.updatedAt = nowIso()
  saveStore()
  logActivity(req.user.id, 'admin.institution-settings.restore-default', {})
  res.json({ ...store.institutionSettings, canEdit: true, restoredDefault: true })
})

app.get('/api/admin/rbac/roles', auth, requireRole(['admin', 'super_admin']), (_req, res) => {
  const rows = RBAC_ROLES.map((role) => ({ role, permissions: permissionsForRole(role) }))
  res.json(rows)
})

app.post('/api/admin/rbac/roles', auth, requireRole(['super_admin']), (req, res) => {
  const role = normalizeRoleName(req.body.role)
  const permissions = Array.isArray(req.body.permissions) ? req.body.permissions.map(String) : []
  if (!role) return res.status(400).json({ error: 'Role name is required' })
  if (RBAC_ROLES.includes(role)) return res.status(409).json({ error: 'Role already exists' })
  RBAC_ROLES.push(role)
  store.rbacRoles[role] = permissions
  saveStore()
  logActivity(req.user.id, 'rbac.role.create', { role, permissionsCount: permissions.length })
  res.status(201).json({ role, permissions })
})

app.delete('/api/admin/rbac/roles/:role', auth, requireRole(['super_admin']), (req, res) => {
  const role = normalizeRoleName(req.params.role)
  if (role === 'super_admin') return res.status(403).json({ error: 'Cannot delete super_admin role' })
  if (!RBAC_ROLES.includes(role)) return res.status(404).json({ error: 'Role not found' })
  const assigned = (store.userRoleAssignments || []).find((a) => a.accessRole === role)
  if (assigned) return res.status(400).json({ error: 'Cannot delete role while assigned to users' })
  const index = RBAC_ROLES.indexOf(role)
  if (index !== -1) RBAC_ROLES.splice(index, 1)
  delete store.rbacRoles[role]
  saveStore()
  logActivity(req.user.id, 'rbac.role.delete', { role })
  res.json({ ok: true })
})

app.get('/api/admin/rbac/permissions', auth, requireRole(['admin', 'super_admin']), (_req, res) => {
  const all = [...new Set(Object.values(DEFAULT_ROLE_PERMISSIONS).flat().filter((p) => p !== '*'))].sort()
  res.json(all)
})

app.patch('/api/admin/rbac/roles/:role', auth, requireRole(['super_admin']), (req, res) => {
  const role = normalizeRoleName(req.params.role)
  if (!RBAC_ROLES.includes(role)) return res.status(404).json({ error: 'Role not found' })
  const permissions = Array.isArray(req.body.permissions) ? req.body.permissions.map(String) : null
  if (!permissions) return res.status(400).json({ error: 'permissions array is required' })
  store.rbacRoles[role] = permissions
  saveStore()
  logActivity(req.user.id, 'rbac.role.update', { role, permissionsCount: permissions.length })
  res.json({ role, permissions: store.rbacRoles[role] })
})

app.get('/api/admin/rbac/users', auth, requireRole(['admin', 'super_admin']), (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.user.findMany({
      select: { id: true, name: true, email: true, role: true },
      orderBy: { id: 'asc' }
    }).then((users) => {
      const rows = users.map((u) => {
        const accessRole = getAssignedAccessRole(u.id) || normalizeRoleName(roleFromDb(u.role))
        return {
          userId: u.id,
          name: u.name,
          email: u.email,
          baseRole: normalizeRoleName(roleFromDb(u.role)),
          accessRole,
          permissions: permissionsForRole(accessRole)
        }
      })
      res.json(rows)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load RBAC users' })
    })
    return
  }
  const rows = store.users.map((u) => ({
    userId: u.id,
    name: u.name,
    email: u.email,
    baseRole: normalizeRoleName(u.role),
    accessRole: getEffectiveRole(u),
    permissions: permissionsForRole(getEffectiveRole(u))
  }))
  res.json(rows)
})

app.get('/api/admin/rbac/role-assignments/history', auth, requireRole(['admin', 'super_admin']), (_req, res) => {
  const logs = (store.activityLogs || [])
    .filter((l) => l.action === 'rbac.user-role.update')
    .slice(-200)
    .map((l) => {
      const changedBy = store.users.find((u) => u.id === l.userId)
      const userId = Number(l.details?.userId)
      const target = store.users.find((u) => u.id === userId)
      return {
        id: l.id,
        timestamp: l.createdAt,
        changedById: l.userId,
        changedByName: changedBy?.name || changedBy?.email || 'Unknown',
        userId,
        userName: target?.name || target?.email || 'Unknown',
        oldRole: l.details?.oldRole || null,
        newRole: l.details?.newRole || null
      }
    })
  res.json(logs)
})

app.patch('/api/admin/rbac/users/:id/role', auth, requireRole(['admin', 'super_admin']), (req, res) => {
  const userId = Number(req.params.id)
  const accessRole = normalizeRoleName(req.body.accessRole)
  if (!RBAC_ROLES.includes(accessRole)) return res.status(400).json({ error: `accessRole must be one of: ${RBAC_ROLES.join(', ')}` })
  const oldAccess = getAssignedAccessRole(userId)
  const persistAssignment = (baseRole) => {
    store.userRoleAssignments = (store.userRoleAssignments || []).filter((a) => a.userId !== userId)
    store.userRoleAssignments.push({ userId, accessRole, updatedAt: nowIso() })
    saveStore()
    logActivity(req.user.id, 'rbac.user-role.update', { userId, oldRole: oldAccess, newRole: accessRole })
    res.json({ userId, accessRole, baseRole, permissions: permissionsForRole(accessRole) })
  }
  const user = store.users.find((u) => u.id === userId)
  if (user) {
    user.role = dbRoleForAccessRole(accessRole)
    return persistAssignment(user.role)
  }
  if (STORAGE_ENGINE === 'prisma') {
    prisma.user.findUnique({ where: { id: userId } }).then((dbUser) => {
      if (!dbUser) return res.status(404).json({ error: 'User not found' })
      return prisma.user.update({
        where: { id: userId },
        data: { role: roleToDb(accessRole) }
      }).then((updated) => persistAssignment(roleFromDb(updated.role)))
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to assign user role' })
    })
    return
  }
  return res.status(404).json({ error: 'User not found' })
})

app.post('/api/admin/bulk-import', auth, requireRole(['admin']), async (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    return res.status(501).json({ error: 'Bulk import not enabled for Prisma storage yet.' })
  }
  const moduleKey = String(req.body.module || '').trim()
  const rows = Array.isArray(req.body.rows) ? req.body.rows : []
  if (!moduleKey) return res.status(400).json({ error: 'module is required' })
  if (!rows.length) return res.status(400).json({ error: 'rows array is required' })

  const config = bulkModuleConfigs()[moduleKey]
  if (!config) return res.status(400).json({ error: 'Unsupported import module' })
  if (moduleKey === 'users' && !EMAIL_ENABLED) {
    return res.status(400).json({ error: 'Email transport not configured. Configure SMTP before importing users.' })
  }
  const collection = config.collection
  if (!Array.isArray(store[collection])) store[collection] = []

  const result = { imported: 0, skipped: 0, errors: [] }
  const uniqueFields = config.uniqueBy || []

  for (const [idx, raw] of rows.entries()) {
    try {
      const normalized = normalizeBulkRow(raw, config.fields)
      const payload = {}
      Object.entries(config.fields).forEach(([field, type]) => {
        if (normalized[field] !== undefined) payload[field] = castBulkValue(normalized[field], type)
      })
      const required = config.required || []
      const missingRequired = required.filter((field) => payload[field] === undefined || payload[field] === '')
      if (missingRequired.length) {
        result.errors.push({ row: idx + 1, error: `Missing required fields: ${missingRequired.join(', ')}` })
        return
      }

      if (uniqueFields.length) {
        const dup = store[collection].find((item) => uniqueFields.some((field) => String(item[field] || '').toLowerCase() === String(payload[field] || '').toLowerCase()))
        if (dup) {
          result.skipped += 1
          return
        }
      }

      if (moduleKey === 'users') {
        const userRole = normalizeRoleName(payload.role || 'student')
        const tempPassword = payload.password || generateTemporaryPassword()
        const user = {
          id: nextId('users'),
          name: payload.name || 'User',
          email: payload.email,
          role: dbRoleForAccessRole(userRole),
          password: bcrypt.hashSync(tempPassword, 10),
          twoFactorEnabled: false
        }
        store.users.push(user)
        const username = ensureUniqueUsername(generateUsername(user.name, payload.personNumber || `USR${user.id}`))
        upsertAccountProfile(user.id, {
          username,
          personNumber: payload.personNumber || '',
          phone: payload.phone || '',
          mustChangePassword: true
        })
        try {
          await sendTemporaryPasswordEmail(user.email, username, tempPassword)
        } catch (error) {
          console.error('bulk user email failed', error)
          result.errors.push({ row: idx + 1, error: 'Failed to send credentials email' })
        }
        result.imported += 1
        continue
      }

      if (moduleKey === 'exam-schedules') {
        const course = store.courses.find((c) => c.id === Number(payload.courseId))
          || store.hierarchyCourses.find((c) => c.id === Number(payload.courseId))
        if (!course) {
          result.errors.push({ row: idx + 1, error: 'Course not found for exam schedule' })
          return
        }
        payload.courseCode = course.code
        payload.courseTitle = course.title
      }

      if (moduleKey === 'exam-papers') {
        const course = store.courses.find((c) => c.id === Number(payload.courseId))
          || store.hierarchyCourses.find((c) => c.id === Number(payload.courseId))
        if (!course) {
          result.errors.push({ row: idx + 1, error: 'Course not found for exam paper' })
          return
        }
        payload.courseCode = course.code
        payload.createdBy = payload.createdBy || req.user.id
      }

      if (moduleKey === 'exam-marks') {
        const calc = computeExamTotals(payload.catMarks || 0, payload.assignmentMarks || 0, payload.examMarks || 0)
        payload.totalMarks = calc.totalMarks
        payload.grade = calc.grade
        payload.submittedBy = payload.submittedBy || req.user.id
        payload.createdAt = nowIso()
      }

      if (moduleKey === 'academic-years' && payload.isActive) {
        store.academicYears.forEach((y) => { y.isActive = false })
      }

      const row = { id: nextId(collection), ...payload }
      store[collection].push(row)
      result.imported += 1
    } catch (error) {
      result.errors.push({ row: idx + 1, error: error.message })
    }
  }

  saveStore()
  logActivity(req.user.id, 'admin.bulk-import', { module: moduleKey, imported: result.imported, skipped: result.skipped })
  res.json(result)
})

app.post('/api/admin/bulk-delete', auth, requireRole(['admin']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    return res.status(501).json({ error: 'Bulk delete not enabled for Prisma storage yet.' })
  }
  const moduleKey = String(req.body.module || '').trim()
  const ids = Array.isArray(req.body.ids) ? req.body.ids.map((id) => Number(id)) : []
  if (!moduleKey) return res.status(400).json({ error: 'module is required' })
  if (!ids.length) return res.status(400).json({ error: 'ids array is required' })

  const deleteMap = {
    enrollment: 'admissions',
    finance: 'feeStructures',
    registrations: 'registrationApprovals'
  }
  const config = bulkModuleConfigs()[moduleKey] || bulkModuleConfigs()[deleteMap[moduleKey]]
  if (!config) return res.status(400).json({ error: 'Unsupported delete module' })
  const collection = config.collection

  if (moduleKey === 'users') {
    ids.forEach((id) => {
      store.users = store.users.filter((u) => u.id !== id)
      cascadeDeleteUserDataJson(id)
    })
    saveStore()
    logActivity(req.user.id, 'admin.bulk-delete', { module: moduleKey, deleted: ids.length })
    return res.json({ ok: true, deleted: ids.length })
  }

  const before = store[collection]?.length || 0
  store[collection] = (store[collection] || []).filter((item) => !ids.includes(Number(item.id)))
  const deleted = before - store[collection].length
  saveStore()
  logActivity(req.user.id, 'admin.bulk-delete', { module: moduleKey, deleted })
  res.json({ ok: true, deleted })
})

app.get('/api/admin/hierarchy/overview', auth, requireRole(['admin']), (_req, res) => {
  const departments = store.hierarchyDepartments.map((d) => ({
    ...d,
    facultyName: store.faculties.find((f) => f.id === d.facultyId)?.name || '-',
    programCount: store.hierarchyPrograms.filter((p) => p.departmentId === d.id).length
  }))
  const programs = store.hierarchyPrograms.map((p) => ({
    ...p,
    departmentName: store.hierarchyDepartments.find((d) => d.id === p.departmentId)?.name || '-'
  }))
  const courses = store.hierarchyCourses.map((c) => ({
    ...c,
    programName: store.hierarchyPrograms.find((p) => p.id === c.programId)?.name || '-'
  }))
  res.json({
    summary: {
      faculties: store.faculties.length,
      departments: store.hierarchyDepartments.length,
      programs: store.hierarchyPrograms.length,
      courses: store.hierarchyCourses.length,
      academicYears: store.academicYears.length,
      semesters: store.hierarchySemesters.length
    },
    faculties: store.faculties,
    departments,
    programs,
    courses,
    academicYears: store.academicYears,
    semesters: store.hierarchySemesters
  })
})

app.get('/api/admin/hierarchy/faculties', auth, requireRole(['admin']), (_req, res) => {
  res.json(store.faculties)
})
app.post('/api/admin/hierarchy/faculties', auth, requireRole(['admin']), (req, res) => {
  const row = { id: nextId('faculties'), name: req.body.name, code: req.body.code || String(req.body.name || '').slice(0, 3).toUpperCase() }
  store.faculties.push(row); saveStore(); logActivity(req.user.id, 'hierarchy.faculty.create', { id: row.id }); res.status(201).json(row)
})
app.patch('/api/admin/hierarchy/faculties/:id', auth, requireRole(['admin']), (req, res) => {
  const row = store.faculties.find((r) => r.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Faculty not found' })
  if (req.body.name !== undefined) row.name = req.body.name
  if (req.body.code !== undefined) row.code = req.body.code
  saveStore(); logActivity(req.user.id, 'hierarchy.faculty.update', { id: row.id }); res.json(row)
})
app.delete('/api/admin/hierarchy/faculties/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  const index = store.faculties.findIndex((r) => r.id === id)
  if (index === -1) return res.status(404).json({ error: 'Faculty not found' })
  store.hierarchyDepartments = store.hierarchyDepartments.filter((d) => d.facultyId !== id)
  const deptIds = store.hierarchyDepartments.map((d) => d.id)
  store.hierarchyPrograms = store.hierarchyPrograms.filter((p) => deptIds.includes(p.departmentId))
  const programIds = store.hierarchyPrograms.map((p) => p.id)
  store.hierarchyCourses = store.hierarchyCourses.filter((c) => programIds.includes(c.programId))
  const [removed] = store.faculties.splice(index, 1)
  saveStore(); logActivity(req.user.id, 'hierarchy.faculty.delete', { id: removed.id }); res.json({ ok: true, deletedId: removed.id })
})

app.get('/api/admin/hierarchy/departments', auth, requireRole(['admin']), (_req, res) => {
  const rows = store.hierarchyDepartments.map((d) => ({
    ...d,
    facultyName: store.faculties.find((f) => f.id === d.facultyId)?.name || '-',
    programCount: store.hierarchyPrograms.filter((p) => p.departmentId === d.id).length
  }))
  res.json(rows)
})
app.post('/api/admin/hierarchy/departments', auth, requireRole(['admin']), (req, res) => {
  const row = {
    id: nextId('hierarchyDepartments'),
    name: req.body.name,
    code: req.body.code || String(req.body.name || '').slice(0, 4).toUpperCase(),
    facultyId: Number(req.body.facultyId),
    hodName: req.body.hodName || ''
  }
  store.hierarchyDepartments.push(row); saveStore(); logActivity(req.user.id, 'hierarchy.department.create', { id: row.id }); res.status(201).json(row)
})
app.patch('/api/admin/hierarchy/departments/:id', auth, requireRole(['admin']), (req, res) => {
  const row = store.hierarchyDepartments.find((r) => r.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Department not found' })
  if (req.body.name !== undefined) row.name = req.body.name
  if (req.body.code !== undefined) row.code = req.body.code
  if (req.body.facultyId !== undefined) row.facultyId = Number(req.body.facultyId)
  if (req.body.hodName !== undefined) row.hodName = req.body.hodName
  saveStore(); logActivity(req.user.id, 'hierarchy.department.update', { id: row.id }); res.json(row)
})
app.delete('/api/admin/hierarchy/departments/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  const index = store.hierarchyDepartments.findIndex((r) => r.id === id)
  if (index === -1) return res.status(404).json({ error: 'Department not found' })
  store.hierarchyPrograms = store.hierarchyPrograms.filter((p) => p.departmentId !== id)
  const programIds = store.hierarchyPrograms.map((p) => p.id)
  store.hierarchyCourses = store.hierarchyCourses.filter((c) => programIds.includes(c.programId))
  const [removed] = store.hierarchyDepartments.splice(index, 1)
  saveStore(); logActivity(req.user.id, 'hierarchy.department.delete', { id: removed.id }); res.json({ ok: true, deletedId: removed.id })
})

app.get('/api/admin/hierarchy/programs', auth, requireRole(['admin']), (_req, res) => {
  const rows = store.hierarchyPrograms.map((p) => ({
    ...p,
    departmentName: store.hierarchyDepartments.find((d) => d.id === p.departmentId)?.name || '-'
  }))
  res.json(rows)
})
app.post('/api/admin/hierarchy/programs', auth, requireRole(['admin']), (req, res) => {
  const row = {
    id: nextId('hierarchyPrograms'),
    name: req.body.name,
    code: req.body.code || String(req.body.name || '').slice(0, 5).toUpperCase(),
    departmentId: Number(req.body.departmentId),
    durationYears: Number(req.body.durationYears || 4),
    awardType: req.body.awardType || 'Degree',
    mode: req.body.mode || 'Full-time'
  }
  store.hierarchyPrograms.push(row); saveStore(); logActivity(req.user.id, 'hierarchy.program.create', { id: row.id }); res.status(201).json(row)
})
app.patch('/api/admin/hierarchy/programs/:id', auth, requireRole(['admin']), (req, res) => {
  const row = store.hierarchyPrograms.find((r) => r.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Program not found' })
  Object.assign(row, {
    name: req.body.name ?? row.name,
    code: req.body.code ?? row.code,
    departmentId: req.body.departmentId !== undefined ? Number(req.body.departmentId) : row.departmentId,
    durationYears: req.body.durationYears !== undefined ? Number(req.body.durationYears) : row.durationYears,
    awardType: req.body.awardType ?? row.awardType,
    mode: req.body.mode ?? row.mode
  })
  saveStore(); logActivity(req.user.id, 'hierarchy.program.update', { id: row.id }); res.json(row)
})
app.delete('/api/admin/hierarchy/programs/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  const index = store.hierarchyPrograms.findIndex((r) => r.id === id)
  if (index === -1) return res.status(404).json({ error: 'Program not found' })
  store.hierarchyCourses = store.hierarchyCourses.filter((c) => c.programId !== id)
  const [removed] = store.hierarchyPrograms.splice(index, 1)
  saveStore(); logActivity(req.user.id, 'hierarchy.program.delete', { id: removed.id }); res.json({ ok: true, deletedId: removed.id })
})

app.get('/api/admin/hierarchy/courses', auth, requireRole(['admin']), (_req, res) => {
  const rows = store.hierarchyCourses.map((c) => ({
    ...c,
    programName: store.hierarchyPrograms.find((p) => p.id === c.programId)?.name || '-'
  }))
  res.json(rows)
})
app.post('/api/admin/hierarchy/courses', auth, requireRole(['admin']), (req, res) => {
  const row = {
    id: nextId('hierarchyCourses'),
    code: req.body.code,
    title: req.body.title,
    programId: Number(req.body.programId),
    creditHours: Number(req.body.creditHours || 3),
    year: Number(req.body.year || 1),
    semester: Number(req.body.semester || 1),
    lecturerAssigned: req.body.lecturerAssigned || ''
  }
  store.hierarchyCourses.push(row); saveStore(); logActivity(req.user.id, 'hierarchy.course.create', { id: row.id }); res.status(201).json(row)
})
app.patch('/api/admin/hierarchy/courses/:id', auth, requireRole(['admin']), (req, res) => {
  const row = store.hierarchyCourses.find((r) => r.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Course not found' })
  Object.assign(row, {
    code: req.body.code ?? row.code,
    title: req.body.title ?? row.title,
    programId: req.body.programId !== undefined ? Number(req.body.programId) : row.programId,
    creditHours: req.body.creditHours !== undefined ? Number(req.body.creditHours) : row.creditHours,
    year: req.body.year !== undefined ? Number(req.body.year) : row.year,
    semester: req.body.semester !== undefined ? Number(req.body.semester) : row.semester,
    lecturerAssigned: req.body.lecturerAssigned ?? row.lecturerAssigned
  })
  saveStore(); logActivity(req.user.id, 'hierarchy.course.update', { id: row.id }); res.json(row)
})
app.delete('/api/admin/hierarchy/courses/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  const index = store.hierarchyCourses.findIndex((r) => r.id === id)
  if (index === -1) return res.status(404).json({ error: 'Course not found' })
  const [removed] = store.hierarchyCourses.splice(index, 1)
  saveStore(); logActivity(req.user.id, 'hierarchy.course.delete', { id: removed.id }); res.json({ ok: true, deletedId: removed.id })
})

app.get('/api/admin/hierarchy/academic-years', auth, requireRole(['admin']), (_req, res) => {
  const rows = store.academicYears.map((y) => ({
    ...y,
    semesters: store.hierarchySemesters.filter((s) => s.academicYearId === y.id).length
  }))
  res.json(rows)
})
app.post('/api/admin/hierarchy/academic-years', auth, requireRole(['admin']), (req, res) => {
  const row = { id: nextId('academicYears'), name: req.body.name, isActive: Boolean(req.body.isActive) }
  if (row.isActive) store.academicYears.forEach((y) => { y.isActive = false })
  store.academicYears.push(row); saveStore(); logActivity(req.user.id, 'hierarchy.academic-year.create', { id: row.id }); res.status(201).json(row)
})
app.patch('/api/admin/hierarchy/academic-years/:id', auth, requireRole(['admin']), (req, res) => {
  const row = store.academicYears.find((r) => r.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Academic year not found' })
  if (req.body.name !== undefined) row.name = req.body.name
  if (req.body.isActive !== undefined) {
    if (Boolean(req.body.isActive)) store.academicYears.forEach((y) => { y.isActive = false })
    row.isActive = Boolean(req.body.isActive)
  }
  saveStore(); logActivity(req.user.id, 'hierarchy.academic-year.update', { id: row.id }); res.json(row)
})
app.delete('/api/admin/hierarchy/academic-years/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  const index = store.academicYears.findIndex((r) => r.id === id)
  if (index === -1) return res.status(404).json({ error: 'Academic year not found' })
  store.hierarchySemesters = store.hierarchySemesters.filter((s) => s.academicYearId !== id)
  const [removed] = store.academicYears.splice(index, 1)
  saveStore(); logActivity(req.user.id, 'hierarchy.academic-year.delete', { id: removed.id }); res.json({ ok: true, deletedId: removed.id })
})

app.get('/api/admin/hierarchy/semesters', auth, requireRole(['admin']), (_req, res) => {
  const rows = store.hierarchySemesters.map((s) => ({
    ...s,
    academicYearName: store.academicYears.find((y) => y.id === s.academicYearId)?.name || '-'
  }))
  res.json(rows)
})
app.post('/api/admin/hierarchy/semesters', auth, requireRole(['admin']), (req, res) => {
  const row = {
    id: nextId('hierarchySemesters'),
    academicYearId: Number(req.body.academicYearId),
    name: req.body.name || 'Semester',
    registrationOpen: req.body.registrationOpen || '',
    registrationClose: req.body.registrationClose || '',
    gradesLocked: req.body.gradesLocked !== undefined ? Boolean(req.body.gradesLocked) : false,
    resultsPublished: req.body.resultsPublished !== undefined ? Boolean(req.body.resultsPublished) : false,
    attendanceLocked: req.body.attendanceLocked !== undefined ? Boolean(req.body.attendanceLocked) : false
  }
  store.hierarchySemesters.push(row); saveStore(); logActivity(req.user.id, 'hierarchy.semester.create', { id: row.id }); res.status(201).json(row)
})
app.patch('/api/admin/hierarchy/semesters/:id', auth, requireRole(['admin']), (req, res) => {
  const row = store.hierarchySemesters.find((r) => r.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Semester not found' })
  Object.assign(row, {
    academicYearId: req.body.academicYearId !== undefined ? Number(req.body.academicYearId) : row.academicYearId,
    name: req.body.name ?? row.name,
    registrationOpen: req.body.registrationOpen ?? row.registrationOpen,
    registrationClose: req.body.registrationClose ?? row.registrationClose,
    gradesLocked: req.body.gradesLocked !== undefined ? Boolean(req.body.gradesLocked) : row.gradesLocked,
    resultsPublished: req.body.resultsPublished !== undefined ? Boolean(req.body.resultsPublished) : row.resultsPublished,
    attendanceLocked: req.body.attendanceLocked !== undefined ? Boolean(req.body.attendanceLocked) : row.attendanceLocked
  })
  saveStore(); logActivity(req.user.id, 'hierarchy.semester.update', { id: row.id }); res.json(row)
})
app.delete('/api/admin/hierarchy/semesters/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  const index = store.hierarchySemesters.findIndex((r) => r.id === id)
  if (index === -1) return res.status(404).json({ error: 'Semester not found' })
  const [removed] = store.hierarchySemesters.splice(index, 1)
  saveStore(); logActivity(req.user.id, 'hierarchy.semester.delete', { id: removed.id }); res.json({ ok: true, deletedId: removed.id })
})

app.get('/api/admin/registration-policy', auth, requireRole(['admin']), (_req, res) => {
  res.json(store.registrationPolicy || {})
})

app.patch('/api/admin/registration-policy', auth, requireRole(['admin']), (req, res) => {
  const policy = store.registrationPolicy || {}
  const updates = req.body || {}
  const next = {
    ...policy,
    maxCredits: updates.maxCredits ?? policy.maxCredits,
    minCredits: updates.minCredits ?? policy.minCredits,
    minGpa: updates.minGpa ?? policy.minGpa,
    feeThresholdPercent: updates.feeThresholdPercent ?? policy.feeThresholdPercent,
    approvalModel: updates.approvalModel ?? policy.approvalModel
  }
  store.registrationPolicy = next
  saveStore()
  res.json(next)
})

app.get('/api/admin/registrations', auth, requireRole(['admin']), async (req, res) => {
  const status = String(req.query.status || '').toLowerCase()
  const records = (store.userVerifications || []).filter((r) => !status || String(r.status || '').toLowerCase() === status)
  const rows = []
  for (const record of records) {
    rows.push(await registrationView(record))
  }
  res.json(rows)
})

app.patch('/api/admin/registrations/:id/approve', auth, requireRole(['admin']), (req, res) => {
  const record = findVerificationById(req.params.id)
  if (!record) return res.status(404).json({ error: 'Registration not found' })
  record.status = 'verified'
  record.verifiedAt = nowIso()
  record.verifiedBy = 'admin'
  record.updatedAt = nowIso()
  saveStore()
  logRegistrationEvent('admin.approve', { userId: record.userId })
  res.json({ ok: true, status: record.status })
})

app.patch('/api/admin/registrations/:id/reject', auth, requireRole(['admin']), (req, res) => {
  const record = findVerificationById(req.params.id)
  if (!record) return res.status(404).json({ error: 'Registration not found' })
  record.status = 'rejected'
  record.rejectedAt = nowIso()
  record.rejectedReason = req.body?.reason || 'Rejected by admin'
  record.updatedAt = nowIso()
  saveStore()
  logRegistrationEvent('admin.reject', { userId: record.userId, reason: record.rejectedReason })
  res.json({ ok: true, status: record.status })
})

app.patch('/api/admin/registrations/:id/reset', auth, requireRole(['admin']), (req, res) => {
  const record = findVerificationById(req.params.id)
  if (!record) return res.status(404).json({ error: 'Registration not found' })
  const refreshed = createOrRefreshVerification(record.userId, record.email || '')
  logRegistrationEvent('admin.reset', { userId: record.userId })
  sendVerificationEmail(refreshed.email, refreshed.emailToken, refreshed.emailExpiresAt)
    .then(() => sendVerificationOtp(refreshed.email, refreshed.otp, refreshed.otpExpiresAt))
    .then(() => res.json({
      ok: true,
      verification: {
        id: refreshed.id,
        email: maskEmail(refreshed.email),
        channels: ['email', 'otp']
      }
    }))
    .catch((error) => {
      console.error('verification email send failed', error)
      res.status(500).json({ error: 'Failed to send verification. Check email configuration and try again.' })
    })
})

async function findRegistryRecord(regNumber, role) {
  if (!regNumber) return null
  const norm = String(regNumber || '').trim().toLowerCase()
  const accessRole = normalizeRoleName(role)

  if (STORAGE_ENGINE === 'prisma' && prisma) {
    const record = await prisma.registrationRecord.findUnique({ where: { regNumber: norm } })
    if (!record) return null
    if (normalizeRoleName(record.role) !== accessRole) return null
    return record
  }

  if (accessRole === 'student') {
    return (store.registrationStudents || []).find((r) => String(r.regNumber || '').trim().toLowerCase() === norm)
  }
  if (accessRole === 'lecturer') {
    return (store.registrationLecturers || []).find((r) => String(r.regNumber || '').trim().toLowerCase() === norm)
  }
  if (accessRole === 'staff') {
    return (store.registrationStaff || []).find((r) => String(r.regNumber || '').trim().toLowerCase() === norm)
  }
  return null
}

function isPasswordStrong(password) {
  if (!password || typeof password !== 'string') return false
  return password.length >= 8 && /[0-9]/.test(password) && /[A-Z]/.test(password) && /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)
}

function maskEmail(email) {
  const value = String(email || '').trim()
  if (!value.includes('@')) return value
  const [name, domain] = value.split('@')
  if (!name) return value
  const head = name.slice(0, 2)
  const tail = name.length > 2 ? name.slice(-1) : ''
  return `${head}${'*'.repeat(Math.max(0, name.length - 3))}${tail}@${domain}`
}

function getMailer() {
  if (!EMAIL_ENABLED) return null
  if (!mailer) {
    mailer = nodemailer.createTransport({
      host: EMAIL_HOST,
      port: EMAIL_PORT,
      secure: EMAIL_SECURE,
      auth: { user: EMAIL_USER, pass: EMAIL_PASS }
    })
  }
  return mailer
}

async function sendEmail({ to, subject, text, html }) {
  const transporter = getMailer()
  if (!transporter) throw new Error('Email transport not configured')
  if (!to) throw new Error('Recipient email is missing')
  return transporter.sendMail({
    from: EMAIL_FROM,
    replyTo: EMAIL_REPLY_TO || undefined,
    to,
    subject,
    text,
    html
  })
}

async function sendVerificationEmail(toEmail, token, expiresAt) {
  const subject = 'Verify your portal account'
  const text = [
    'Use the verification token below to activate your portal account.',
    `Token: ${token}`,
    `Expires: ${expiresAt}`,
    'If you did not request this, please ignore this email.'
  ].join('\n')
  const html = `
    <p>Use the verification token below to activate your portal account.</p>
    <p><b>Token:</b> ${token}</p>
    <p><b>Expires:</b> ${expiresAt}</p>
    <p>If you did not request this, please ignore this email.</p>
  `
  await sendEmail({ to: toEmail, subject, text, html })
}

async function sendVerificationOtp(toEmail, otp, expiresAt) {
  const subject = 'Your portal OTP code'
  const text = [
    'Use the OTP code below to verify your portal account.',
    `OTP: ${otp}`,
    `Expires: ${expiresAt}`,
    'If you did not request this, please ignore this email.'
  ].join('\n')
  const html = `
    <p>Use the OTP code below to verify your portal account.</p>
    <p><b>OTP:</b> ${otp}</p>
    <p><b>Expires:</b> ${expiresAt}</p>
    <p>If you did not request this, please ignore this email.</p>
  `
  await sendEmail({ to: toEmail, subject, text, html })
}

async function sendPasswordResetEmail(toEmail, token, expiresAt) {
  const subject = 'Reset your portal password'
  const text = [
    'Use the reset token below to change your password.',
    `Token: ${token}`,
    `Expires: ${expiresAt.toISOString()}`,
    'If you did not request this, please ignore this email.'
  ].join('\n')
  const html = `
    <p>Use the reset token below to change your password.</p>
    <p><b>Token:</b> ${token}</p>
    <p><b>Expires:</b> ${expiresAt.toISOString()}</p>
    <p>If you did not request this, please ignore this email.</p>
  `
  await sendEmail({ to: toEmail, subject, text, html })
}

async function sendTemporaryPasswordEmail(toEmail, username, tempPassword) {
  const subject = 'Your portal account credentials'
  const text = [
    'Your portal account has been created or reset.',
    `Username: ${username || toEmail}`,
    `Temporary password: ${tempPassword}`,
    'Please change your password after logging in.'
  ].join('\n')
  const html = `
    <p>Your portal account has been created or reset.</p>
    <p><b>Username:</b> ${username || toEmail}</p>
    <p><b>Temporary password:</b> ${tempPassword}</p>
    <p>Please change your password after logging in.</p>
  `
  await sendEmail({ to: toEmail, subject, text, html })
}

async function resolveNotificationRecipients(audience, toUserId) {
  if (audience === 'all') {
    if (STORAGE_ENGINE === 'prisma' && prisma) {
      return prisma.user.findMany({ select: { id: true, email: true } })
    }
    return (store.users || []).map((u) => ({ id: u.id, email: u.email }))
  }
  const user = await findUserById(toUserId)
  return user ? [{ id: user.id, email: user.email }] : []
}

async function sendNotificationEmail({ audience, toUserId, message }) {
  const recipients = await resolveNotificationRecipients(audience, toUserId)
  const subject = 'Portal Notification'
  const tasks = recipients
    .filter((r) => r.email)
    .map((r) => sendEmail({ to: r.email, subject, text: message, html: `<p>${message}</p>` }))
  await Promise.all(tasks)
}

function randomToken(length = 32) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let out = ''
  for (let i = 0; i < length; i += 1) out += chars.charAt(Math.floor(Math.random() * chars.length))
  return out
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000))
}

function findVerificationById(id) {
  return (store.userVerifications || []).find((v) => v.id === Number(id))
}

function findVerificationForUser(userId) {
  return (store.userVerifications || []).find((v) => v.userId === Number(userId)) || null
}

function createOrRefreshVerification(userId, email) {
  if (!Array.isArray(store.userVerifications)) store.userVerifications = []
  const now = Date.now()
  const otpExpiresAt = new Date(now + 15 * 60 * 1000).toISOString()
  const emailExpiresAt = new Date(now + 24 * 60 * 60 * 1000).toISOString()
  const existing = findVerificationForUser(userId)
  const payload = {
    userId: Number(userId),
    email: email || '',
    otp: generateOtp(),
    emailToken: randomToken(48),
    otpExpiresAt,
    emailExpiresAt,
    status: 'pending',
    createdAt: existing?.createdAt || nowIso(),
    updatedAt: nowIso(),
    lastSentAt: nowIso()
  }
  if (existing) {
    Object.assign(existing, payload)
    saveStore()
    return existing
  }
  const row = { id: nextId('userVerifications'), ...payload }
  store.userVerifications.push(row)
  saveStore()
  return row
}

function verificationStatusForUser(userId) {
  const record = findVerificationForUser(userId)
  if (!record) return { required: false, status: 'none' }
  if (record.status === 'verified') return { required: false, status: 'verified' }
  return { required: true, status: record.status || 'pending', record }
}

function logRegistrationEvent(action, details) {
  if (!Array.isArray(store.registrationLogs)) store.registrationLogs = []
  store.registrationLogs.push({
    id: nextId('registrationLogs'),
    action,
    details: details || {},
    createdAt: nowIso()
  })
  saveStore()
}

async function findUserById(userId) {
  if (STORAGE_ENGINE === 'prisma' && prisma) {
    return prisma.user.findUnique({ where: { id: Number(userId) } })
  }
  return store.users.find((u) => u.id === Number(userId)) || null
}

async function registrationView(record) {
  const user = await findUserById(record.userId)
  const profile = (store.accountProfiles || []).find((p) => p.userId === Number(record.userId)) || {}
  const accessRole = getAssignedAccessRole(record.userId)
  return {
    id: record.id,
    userId: record.userId,
    name: user?.name || '-',
    email: user?.email || record.email || '-',
    role: accessRole || user?.role || '-',
    personNumber: profile.personNumber || '-',
    status: record.status || 'pending',
    verifiedBy: record.verifiedBy || null,
    verifiedAt: record.verifiedAt || null,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt
  }
}

app.post('/api/auth/verify-registration', async (req, res) => {
  const { regNumber, role, dob } = req.body || {}
  if (!regNumber || !role) return res.status(400).json({ error: 'regNumber and role are required' })
  const record = await findRegistryRecord(regNumber, role)
  if (!record) {
    logRegistrationEvent('verify.failed', { regNumber, role })
    return res.status(404).json({ error: 'Registration number not found. Please contact the registrar or administration.' })
  }
  if (dob && record.dob && String(record.dob).slice(0, 10) !== String(dob).slice(0, 10)) {
    logRegistrationEvent('verify.dob-mismatch', { regNumber, role })
    return res.status(400).json({ error: 'Date of birth does not match our records.' })
  }
  logRegistrationEvent('verify.success', { regNumber, role })
  return res.json({ ok: true, record: {
    regNumber: record.regNumber,
    name: record.name,
    program: record.program || null,
    department: record.department || null,
    email: record.email || null,
    position: record.position || null,
    role: normalizeRoleName(role)
  } })
})

app.post('/api/auth/register', async (req, res) => {
  const { email, password, role = 'student', name, username, personNumber, phone, confirmPassword } = req.body
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' })
  const accessRole = normalizeRoleName(role)
  if (!RBAC_ROLES.includes(accessRole)) return res.status(400).json({ error: `Invalid role. Allowed: ${RBAC_ROLES.join(', ')}` })
  if (!personNumber) return res.status(400).json({ error: 'Registration number is required' })
  const registryRecord = await findRegistryRecord(personNumber, accessRole)
  if (!registryRecord) return res.status(400).json({ error: 'Registration number not found. Please contact the registrar or administration.' })
  if (!isPasswordStrong(password)) {
    return res.status(400).json({ error: 'Password must be at least 8 characters and contain at least one number, one uppercase letter, and one symbol.' })
  }
  if (confirmPassword && password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' })
  }
  const generatedUsername = ensureUniqueUsername(username || generateUsername(name || email, personNumber))
  const existingProfile = (store.accountProfiles || []).find((p) => String(p.personNumber || '').toLowerCase() === String(personNumber || '').toLowerCase())
  if (existingProfile) {
    return res.status(409).json({ error: 'An account already exists with this registration number. Please login or reset your password.' })
  }

  if (STORAGE_ENGINE === 'prisma') {
    const existing = await prisma.user.findUnique({ where: { email } })
    if (existing) return res.status(409).json({ error: 'Email already used' })

    const user = await prisma.user.create({
      data: {
        email,
        name: name || email.split('@')[0],
        role: roleToDb(accessRole),
        password: await bcrypt.hash(password, 10),
        twoFactorEnabled: false
      }
    })
    if (!store.userRoleAssignments.find((a) => a.userId === user.id)) {
      store.userRoleAssignments.push({ userId: user.id, accessRole, updatedAt: nowIso() })
    }
    upsertAccountProfile(user.id, {
      username: generatedUsername,
      personNumber: personNumber || '',
      phone: phone || '',
      mustChangePassword: false
    })
    saveStore()
    logActivity(user.id, 'auth.register', { role })
    const verification = createOrRefreshVerification(user.id, email)
    logRegistrationEvent('register.created', { userId: user.id, role: accessRole })
    try {
      await sendVerificationEmail(email, verification.emailToken, verification.emailExpiresAt)
      await sendVerificationOtp(email, verification.otp, verification.otpExpiresAt)
    } catch (error) {
      console.error('verification email send failed', error)
      return res.status(500).json({ error: 'Failed to send verification. Check email configuration and try again.' })
    }
    return res.status(201).json({
      ok: true,
      verification: {
        id: verification.id,
        email: maskEmail(email),
        channels: ['email', 'otp']
      }
    })
  }

  if (store.users.find((u) => u.email === email)) return res.status(409).json({ error: 'Email already used' })
  const user = {
    id: nextId('users'),
    email,
    name: name || email.split('@')[0],
    role: dbRoleForAccessRole(accessRole),
    password: await bcrypt.hash(password, 10),
    twoFactorEnabled: false
  }
  store.users.push(user)
  store.userRoleAssignments.push({ userId: user.id, accessRole, updatedAt: nowIso() })
  upsertAccountProfile(user.id, {
    username: generatedUsername,
    personNumber: personNumber || '',
    phone: phone || '',
    mustChangePassword: false
  })
  saveStore()
  logActivity(user.id, 'auth.register', { role })

  const verification = createOrRefreshVerification(user.id, email)
  logRegistrationEvent('register.created', { userId: user.id, role: accessRole })
  try {
    await sendVerificationEmail(email, verification.emailToken, verification.emailExpiresAt)
    await sendVerificationOtp(email, verification.otp, verification.otpExpiresAt)
  } catch (error) {
    console.error('verification email send failed', error)
    return res.status(500).json({ error: 'Failed to send verification. Check email configuration and try again.' })
  }
  res.status(201).json({
    ok: true,
    verification: {
      id: verification.id,
      email: maskEmail(email),
      channels: ['email', 'otp']
    }
  })
})

app.post('/api/auth/verify-email', (req, res) => {
  const { verificationId, token } = req.body || {}
  if (!verificationId || !token) return res.status(400).json({ error: 'verificationId and token are required' })
  const record = findVerificationById(verificationId)
  if (!record) return res.status(404).json({ error: 'Verification not found' })
  if (record.status === 'verified') return res.json({ ok: true, status: 'verified' })
  if (record.emailExpiresAt && new Date(record.emailExpiresAt) < new Date()) {
    record.status = 'expired'
    record.updatedAt = nowIso()
    saveStore()
    return res.status(400).json({ error: 'Email verification expired. Please resend verification.' })
  }
  if (String(record.emailToken) !== String(token)) return res.status(400).json({ error: 'Invalid verification token' })
  record.status = 'verified'
  record.verifiedAt = nowIso()
  record.updatedAt = nowIso()
  record.verifiedBy = 'email'
  saveStore()
  logRegistrationEvent('verify.email', { userId: record.userId })
  res.json({ ok: true, status: 'verified' })
})

app.post('/api/auth/verify-otp', (req, res) => {
  const { verificationId, otp } = req.body || {}
  if (!verificationId || !otp) return res.status(400).json({ error: 'verificationId and otp are required' })
  const record = findVerificationById(verificationId)
  if (!record) return res.status(404).json({ error: 'Verification not found' })
  if (record.status === 'verified') return res.json({ ok: true, status: 'verified' })
  if (record.otpExpiresAt && new Date(record.otpExpiresAt) < new Date()) {
    record.status = 'expired'
    record.updatedAt = nowIso()
    saveStore()
    return res.status(400).json({ error: 'OTP expired. Please resend OTP.' })
  }
  if (String(record.otp) !== String(otp)) return res.status(400).json({ error: 'Invalid OTP' })
  record.status = 'verified'
  record.verifiedAt = nowIso()
  record.updatedAt = nowIso()
  record.verifiedBy = 'otp'
  saveStore()
  logRegistrationEvent('verify.otp', { userId: record.userId })
  res.json({ ok: true, status: 'verified' })
})

app.post('/api/auth/resend-verification', (req, res) => {
  const { verificationId, channel } = req.body || {}
  if (!verificationId || !channel) return res.status(400).json({ error: 'verificationId and channel are required' })
  const record = findVerificationById(verificationId)
  if (!record) return res.status(404).json({ error: 'Verification not found' })
  const lastSentAt = record.lastSentAt ? new Date(record.lastSentAt).getTime() : 0
  if (Date.now() - lastSentAt < 60000) {
    return res.status(429).json({ error: 'Please wait before requesting another code.' })
  }
  const refreshed = createOrRefreshVerification(record.userId, record.email || '')
  logRegistrationEvent('verify.resend', { userId: record.userId, channel })
  const send = String(channel).toLowerCase() === 'otp'
    ? sendVerificationOtp(refreshed.email, refreshed.otp, refreshed.otpExpiresAt)
    : sendVerificationEmail(refreshed.email, refreshed.emailToken, refreshed.emailExpiresAt)
  send.then(() => res.json({
    ok: true,
    verification: {
      id: refreshed.id,
      email: maskEmail(refreshed.email),
      channels: ['email', 'otp']
    }
  })).catch((error) => {
    console.error('verification resend failed', error)
    res.status(500).json({ error: 'Failed to send verification. Check email configuration and try again.' })
  })
})

app.post('/api/auth/login', async (req, res) => {
  const identifier = String(req.body.identifier || req.body.email || req.body.username || '').trim()
  const { password } = req.body
  if (!identifier || !password) return res.status(400).json({ error: 'identifier/email/username and password are required' })
  const byProfile = (store.accountProfiles || []).find((p) => String(p.username || '').toLowerCase() === identifier.toLowerCase())
  const userRaw = STORAGE_ENGINE === 'prisma'
    ? (byProfile
      ? await prisma.user.findUnique({ where: { id: Number(byProfile.userId) } })
      : await prisma.user.findUnique({ where: { email: identifier } }))
    : (byProfile
      ? store.users.find((u) => u.id === Number(byProfile.userId))
      : store.users.find((u) => u.email === identifier))
  if (!userRaw) return res.status(401).json({ error: 'Invalid credentials' })
  const verification = verificationStatusForUser(userRaw.id || userRaw?.id)
  if (verification.required) {
    return res.status(403).json({
      error: 'Account not verified. Please verify your email or OTP.',
      verificationRequired: true,
      verificationId: verification.record?.id || null
    })
  }

  const ok = await bcrypt.compare(password, userRaw.password)
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' })

  const user = normalizeUserRecord(userRaw)
  const maintenance = getMaintenanceState()
  const effectiveRole = normalizeRoleName(user.effectiveRole || user.role)
  if (maintenance.enabled && !['admin', 'super_admin'].includes(effectiveRole)) {
    return res.status(503).json({ error: maintenance.message, maintenance: true, endsAt: maintenance.endsAt })
  }
  const token = issueToken(user)
  logActivity(user.id, 'auth.login', {})
  res.json({
    token,
    user: userPublicView(user)
  })
})

app.get('/api/auth/me', auth, (req, res) => {
  const { id, email, role, effectiveRole, name, twoFactorEnabled, permissions, username, personNumber, phone, mustChangePassword } = req.user
  res.json({
    id,
    email,
    role: effectiveRole || normalizeRoleName(role),
    baseRole: normalizeRoleName(role),
    name,
    twoFactorEnabled,
    permissions,
    username,
    personNumber,
    phone,
    mustChangePassword
  })
})

app.post('/api/auth/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {}
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'currentPassword and newPassword are required' })
  if (String(newPassword).length < 8) return res.status(400).json({ error: 'newPassword must be at least 8 characters' })
  const currentUser = STORAGE_ENGINE === 'prisma'
    ? await prisma.user.findUnique({ where: { id: req.user.id } })
    : store.users.find((u) => u.id === req.user.id)
  if (!currentUser) return res.status(404).json({ error: 'User not found' })
  const ok = await bcrypt.compare(currentPassword, currentUser.password)
  if (!ok) return res.status(401).json({ error: 'Current password is incorrect' })
  const hash = await bcrypt.hash(newPassword, 10)
  if (STORAGE_ENGINE === 'prisma') {
    await prisma.user.update({ where: { id: req.user.id }, data: { password: hash } })
  } else {
    currentUser.password = hash
  }
  upsertAccountProfile(req.user.id, { mustChangePassword: false })
  saveStore()
  logActivity(req.user.id, 'auth.password.change', {})
  res.json({ ok: true, mustChangePassword: false })
})

app.post('/api/auth/two-factor/enable', auth, (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.user.update({
      where: { id: req.user.id },
      data: { twoFactorEnabled: true }
    }).then(() => {
      logActivity(req.user.id, 'auth.2fa.enable', {})
      res.json({ ok: true, twoFactorEnabled: true })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to enable 2FA' })
    })
    return
  }
  req.user.twoFactorEnabled = true
  saveStore()
  logActivity(req.user.id, 'auth.2fa.enable', {})
  res.json({ ok: true, twoFactorEnabled: true })
})

app.get('/api/catalog/courses', auth, (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.course.findMany({ orderBy: { id: 'asc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load courses' })
      })
    return
  }
  res.json(store.courses)
})

app.get('/api/catalog/semesters', auth, (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.semester.findMany({ orderBy: { startDate: 'asc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load semesters' })
      })
    return
  }
  res.json(store.semesters)
})

app.get('/api/student/dashboard', auth, requireRole(['student']), async (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    const registrations = await prisma.courseRegistration.findMany({
      where: { studentId: req.user.id, status: 'registered' },
      include: { course: true }
    })
    const courseIds = registrations.map((r) => r.courseId)
    const timetable = courseIds.length
      ? await prisma.timetableSlot.findMany({ where: { courseId: { in: courseIds } } })
      : []
    const attendance = await prisma.attendance.findMany({ where: { studentId: req.user.id } })
    const results = buildStudentResults(req.user.id)
    const finance = await ensureFinanceAccountData(req.user.id)

    return res.json({
      profile: { id: req.user.id, name: req.user.name, email: req.user.email },
      registrations,
      timetable,
      attendance,
      results,
      finance
    })
  }

  const registrations = store.courseRegistrations.filter((r) => r.studentId === req.user.id && r.status === 'registered')
  const timetable = store.timetable.filter((slot) => registrations.some((r) => r.courseId === slot.courseId))
  const attendance = store.attendance.filter((row) => row.studentId === req.user.id)
  const results = buildStudentResults(req.user.id)
  const finance = ensureFinanceAccount(req.user.id)

  res.json({
    profile: { id: req.user.id, name: req.user.name, email: req.user.email },
    registrations,
    timetable,
    attendance,
    results,
    finance
  })
})

app.get('/api/student/registration/eligibility', auth, requireRole(['student']), (req, res) => {
  const result = evaluateRegistrationEligibility(req.user.id)
  return res.json(result)
})

app.get('/api/student/registration/available-courses', auth, requireRole(['student']), (req, res) => {
  const check = evaluateRegistrationEligibility(req.user.id)
  if (!check.ok) return res.status(400).json(check)
  const profile = check.profile
  const semester = check.semester
  const courses = store.hierarchyCourses.filter((c) =>
    Number(c.programId) === Number(profile.programId) &&
    Number(c.year) === Number(profile.yearOfStudy) &&
    Number(c.semester) === Number((semester.name || '').match(/\d+/)?.[0] || c.semester)
  )
  return res.json({ semester, profile, courses })
})

app.post('/api/student/course-registrations', auth, requireRole(['student']), (req, res) => {
  const { courseId, courseIds = [], action = 'add' } = req.body
  const check = evaluateRegistrationEligibility(req.user.id)
  if (!check.ok) return res.status(400).json(check)
  const semester = check.semester
  const profile = check.profile
  const policy = check.policy || {}

  if (action === 'drop') {
    const existingDrop = store.courseRegistrations.find((r) => r.studentId === req.user.id && r.courseId === Number(courseId) && r.semesterId === semester.id && r.status !== 'dropped')
    if (!existingDrop) return res.status(400).json({ error: 'Not registered' })
    existingDrop.status = 'dropped'
    existingDrop.updatedAt = nowIso()
    saveStore()
    logActivity(req.user.id, 'student.course.drop', { courseId: Number(courseId) })
    return res.json(existingDrop)
  }

  const selectedIds = courseIds.length ? courseIds.map(Number) : [Number(courseId)]
  const available = store.hierarchyCourses.filter((c) =>
    Number(c.programId) === Number(profile.programId) &&
    Number(c.year) === Number(profile.yearOfStudy) &&
    Number(c.semester) === Number((semester.name || '').match(/\d+/)?.[0] || c.semester)
  )
  const availableIds = new Set(available.map((c) => c.id))
  const selectedCourses = selectedIds.map((id) => store.hierarchyCourses.find((c) => c.id === id)).filter(Boolean)
  if (!selectedCourses.length) return res.status(400).json({ error: 'No courses selected' })
  if (selectedCourses.some((c) => !availableIds.has(c.id))) return res.status(400).json({ error: 'Selected course is not available for your program/year/semester' })

  const existingRegs = store.courseRegistrations.filter((r) => r.studentId === req.user.id && r.semesterId === semester.id && r.status === 'registered')
  const existingCourseIds = new Set(existingRegs.map((r) => r.courseId))
  if (selectedCourses.some((c) => existingCourseIds.has(c.id))) return res.status(409).json({ error: 'Duplicate course registration detected' })

  const totalCreditsSelected = selectedCourses.reduce((sum, c) => sum + Number(c.creditHours || c.credits || 0), 0)
  const totalCreditsCurrent = existingRegs
    .map((r) => store.hierarchyCourses.find((c) => c.id === r.courseId))
    .filter(Boolean)
    .reduce((sum, c) => sum + Number(c.creditHours || c.credits || 0), 0)
  const projected = totalCreditsCurrent + totalCreditsSelected
  if (projected > Number(policy.maxCredits || 24)) return res.status(400).json({ error: `Max credit limit exceeded (${policy.maxCredits || 24})` })
  if (projected < Number(policy.minCredits || 12)) return res.status(400).json({ error: `Minimum credit requirement not met (${policy.minCredits || 12})` })

  for (const course of selectedCourses) {
    const prerequisites = Array.isArray(course.prerequisiteCodes) ? course.prerequisiteCodes : []
    if (!prerequisites.length) continue
    const completedCodes = buildStudentResults(req.user.id).rows.filter((r) => ['A', 'B', 'C', 'D'].includes(r.grade)).map((r) => r.courseCode)
    const missing = prerequisites.filter((code) => !completedCodes.includes(code))
    if (missing.length) return res.status(400).json({ error: `Missing prerequisites for ${course.code}: ${missing.join(', ')}` })
  }

  const approvalRequired = String(policy.approvalModel || 'advisor') !== 'auto'
  const created = selectedCourses.map((course) => {
    const row = {
      id: nextId('courseRegistrations'),
      studentId: req.user.id,
      courseId: course.id,
      semesterId: semester.id,
      status: approvalRequired ? 'pending' : 'registered',
      createdAt: nowIso()
    }
    store.courseRegistrations.push(row)
    return row
  })

  if (approvalRequired) {
    created.forEach((r) => {
      store.registrationApprovals.push({
        id: nextId('registrationApprovals'),
        registrationId: r.id,
        studentId: r.studentId,
        courseId: r.courseId,
        semesterId: semester.id,
        status: 'pending',
        reviewedBy: null,
        createdAt: nowIso()
      })
    })
  } else {
    const invoice = {
      id: nextId('invoices'),
      studentId: req.user.id,
      semesterId: semester.id,
      amount: totalCreditsSelected * 100,
      description: `Tuition invoice for ${semester.name}`,
      status: 'unpaid',
      createdAt: nowIso()
    }
    store.invoices.push(invoice)
    const account = ensureFinanceAccount(req.user.id)
    account.tuitionBalance = Number(account.tuitionBalance || 0) + invoice.amount
    account.updatedAt = nowIso()
  }
  saveStore()
  logActivity(req.user.id, 'student.course.register', { count: created.length, approvalRequired })
  return res.status(201).json({ ok: true, approvalRequired, registrations: created })
})

app.get('/api/student/timetable', auth, requireRole(['student']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.courseRegistration.findMany({
      where: { studentId: req.user.id, status: 'registered' }
    }).then(async (registrations) => {
      const ids = registrations.map((r) => r.courseId)
      if (!ids.length) return res.json([])
      const rows = await prisma.timetableSlot.findMany({ where: { courseId: { in: ids } } })
      return res.json(rows)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load timetable' })
    })
    return
  }
  const registeredCourseIds = store.courseRegistrations
    .filter((r) => r.studentId === req.user.id && r.status === 'registered')
    .map((r) => r.courseId)
  const rows = store.timetable.filter((slot) => registeredCourseIds.includes(slot.courseId))
  res.json(rows)
})

app.get('/api/student/results', auth, requireRole(['student']), async (req, res) => {
  const results = buildStudentResults(req.user.id)
  res.json(results)
})

app.get('/api/student/transcript', auth, requireRole(['student']), async (req, res) => {
  const results = buildStudentResults(req.user.id)
  const transcript = {
    student: { id: req.user.id, name: req.user.name, email: req.user.email },
    issuedAt: nowIso(),
    totalCredits: results.totalCredits,
    cgpa: results.cgpa,
    courses: results.rows
  }
  res.json(transcript)
})

app.get('/api/student/exam-card', auth, requireRole(['student']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.courseRegistration.findMany({
      where: { studentId: req.user.id, status: 'registered' },
      include: { course: true }
    }).then(async (rows) => {
      const semester = await latestSemesterData()
      res.json({
        student: { id: req.user.id, name: req.user.name },
        semester: semester || null,
        courses: rows.map((r) => r.course),
        generatedAt: nowIso()
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to generate exam card' })
    })
    return
  }
  const registered = store.courseRegistrations
    .filter((r) => r.studentId === req.user.id && r.status === 'registered')
    .map((r) => store.courses.find((c) => c.id === r.courseId))
    .filter(Boolean)

  res.json({
    student: { id: req.user.id, name: req.user.name },
    semester: store.semesters[store.semesters.length - 1] || null,
    courses: registered,
    generatedAt: nowIso()
  })
})

app.get('/api/student/assignments', auth, requireRole(['student']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.courseRegistration.findMany({
      where: { studentId: req.user.id, status: 'registered' }
    }).then(async (rows) => {
      const ids = rows.map((r) => r.courseId)
      if (!ids.length) return res.json([])
      const assignments = await prisma.assignment.findMany({ where: { courseId: { in: ids } } })
      return res.json(assignments)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load assignments' })
    })
    return
  }
  const registeredCourseIds = store.courseRegistrations
    .filter((r) => r.studentId === req.user.id && r.status === 'registered')
    .map((r) => r.courseId)
  res.json(store.assignments.filter((a) => registeredCourseIds.includes(a.courseId)))
})

app.post('/api/student/submissions', auth, requireRole(['student']), (req, res) => {
  const { assignmentId, content } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.assignment.findUnique({ where: { id: Number(assignmentId) } }).then((assignment) => {
      if (!assignment) return res.status(404).json({ error: 'Assignment not found' })
      return prisma.submission.create({
        data: {
          assignmentId: assignment.id,
          studentId: req.user.id,
          content: content || 'Submitted via portal'
        }
      }).then((record) => {
        logActivity(req.user.id, 'student.assignment.submit', { assignmentId: assignment.id })
        res.status(201).json(record)
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to submit assignment' })
    })
    return
  }
  const assignment = store.assignments.find((a) => a.id === Number(assignmentId))
  if (!assignment) return res.status(404).json({ error: 'Assignment not found' })

  const record = {
    id: nextId('submissions'),
    assignmentId: assignment.id,
    studentId: req.user.id,
    content: content || 'Submitted via portal',
    submittedAt: nowIso()
  }
  store.submissions.push(record)
  saveStore()
  logActivity(req.user.id, 'student.assignment.submit', { assignmentId: assignment.id })
  res.status(201).json(record)
})

app.get('/api/student/attendance', auth, requireRole(['student']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.attendance.findMany({ where: { studentId: req.user.id }, orderBy: { date: 'desc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load attendance' })
      })
    return
  }
  res.json(store.attendance.filter((a) => a.studentId === req.user.id))
})

app.get('/api/lecturer/dashboard', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    const courseWhere = req.user.role === 'admin' ? {} : { lecturerId: req.user.id }
    prisma.course.findMany({ where: courseWhere }).then(async (courses) => {
      const courseIds = courses.map((c) => c.id)
      const [assignments, materials] = await Promise.all([
        courseIds.length ? prisma.assignment.findMany({ where: { courseId: { in: courseIds } } }) : [],
        courseIds.length ? prisma.material.findMany({ where: { courseId: { in: courseIds } } }) : []
      ])
      res.json({ courses, assignments, materials })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load lecturer dashboard' })
    })
    return
  }
  const myCourses = store.courses.filter((c) => c.lecturerId === req.user.id || req.user.role === 'admin')
  const courseIds = myCourses.map((c) => c.id)
  res.json({
    courses: myCourses,
    assignments: store.assignments.filter((a) => courseIds.includes(a.courseId)),
    materials: store.materials.filter((m) => courseIds.includes(m.courseId))
  })
})

app.post('/api/lecturer/materials', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const { courseId, title, url } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.course.findUnique({ where: { id: Number(courseId) } }).then((course) => {
      if (!course) return res.status(404).json({ error: 'Course not found' })
      return prisma.material.create({
        data: {
          courseId: course.id,
          title: title || 'Course Material',
          url: url || '#',
          uploadedBy: req.user.id
        }
      }).then((material) => {
        logActivity(req.user.id, 'lecturer.material.upload', { courseId: course.id })
        res.status(201).json(material)
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to upload material' })
    })
    return
  }
  const course = store.courses.find((c) => c.id === Number(courseId))
  if (!course) return res.status(404).json({ error: 'Course not found' })

  const material = {
    id: nextId('materials'),
    courseId: course.id,
    title: title || 'Course Material',
    url: url || '#',
    uploadedBy: req.user.id,
    uploadedAt: nowIso()
  }
  store.materials.push(material)
  saveStore()
  logActivity(req.user.id, 'lecturer.material.upload', { courseId: course.id })
  res.status(201).json(material)
})

app.post('/api/lecturer/assignments', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const { courseId, title, description, dueDate } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.course.findUnique({ where: { id: Number(courseId) } }).then((course) => {
      if (!course) return res.status(404).json({ error: 'Course not found' })
      return prisma.assignment.create({
        data: {
          courseId: course.id,
          title: title || 'New Assignment',
          description: description || '',
          dueDate: dueDate ? new Date(dueDate) : null,
          createdById: req.user.id
        }
      }).then((assignment) => {
        logActivity(req.user.id, 'lecturer.assignment.create', { courseId: course.id, assignmentId: assignment.id })
        res.status(201).json(assignment)
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create assignment' })
    })
    return
  }
  const course = store.courses.find((c) => c.id === Number(courseId))
  if (!course) return res.status(404).json({ error: 'Course not found' })

  const assignment = {
    id: nextId('assignments'),
    courseId: course.id,
    title: title || 'New Assignment',
    description: description || '',
    dueDate: dueDate || null,
    createdBy: req.user.id
  }
  store.assignments.push(assignment)
  saveStore()
  logActivity(req.user.id, 'lecturer.assignment.create', { courseId: course.id, assignmentId: assignment.id })
  res.status(201).json(assignment)
})

app.post('/api/lecturer/attendance', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const { studentId, courseId, present } = req.body
  const semester = getCurrentSemesterForGrading()
  if (semester?.attendanceLocked) {
    return res.status(403).json({ error: 'Attendance is locked for the current semester' })
  }
  if (STORAGE_ENGINE === 'prisma') {
    Promise.all([
      prisma.user.findUnique({ where: { id: Number(studentId) } }),
      prisma.course.findUnique({ where: { id: Number(courseId) } })
    ]).then(([student, course]) => {
      if (!student || roleFromDb(student.role) !== 'student' || !course) {
        return res.status(404).json({ error: 'Student or course not found' })
      }
      return prisma.attendance.create({
        data: {
          studentId: student.id,
          courseId: course.id,
          date: new Date(),
          present: present !== false,
          markedById: req.user.id
        }
      }).then((entry) => {
        logActivity(req.user.id, 'lecturer.attendance.record', { studentId: student.id, courseId: course.id })
        res.status(201).json(entry)
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to record attendance' })
    })
    return
  }
  const student = store.users.find((u) => u.id === Number(studentId) && u.role === 'student')
  const course = store.courses.find((c) => c.id === Number(courseId))
  if (!student || !course) return res.status(404).json({ error: 'Student or course not found' })

  const entry = {
    id: nextId('attendance'),
    studentId: student.id,
    courseId: course.id,
    date: nowIso().slice(0, 10),
    present: present !== false,
    markedBy: req.user.id
  }
  store.attendance.push(entry)
  saveStore()
  logActivity(req.user.id, 'lecturer.attendance.record', { studentId: student.id, courseId: course.id })
  res.status(201).json(entry)
})

app.get('/api/lecturer/grade-entry/:courseId', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const courseId = Number(req.params.courseId)
  const semester = getCurrentSemesterForGrading()
  if (!semester) return res.status(400).json({ error: 'No semester configured' })
  const course = store.hierarchyCourses.find((c) => c.id === courseId) || store.courses.find((c) => c.id === courseId)
  if (!course) return res.status(404).json({ error: 'Course not found' })
  const semesterLocked = semester.gradesLocked === true

  let sheet = store.gradeSheets.find((s) => s.courseId === courseId && s.semesterId === semester.id)
  if (!sheet) {
    sheet = {
      id: nextId('gradeSheets'),
      courseId,
      semesterId: semester.id,
      lecturerId: req.user.id,
      status: 'draft',
      createdAt: nowIso(),
      updatedAt: nowIso()
    }
    store.gradeSheets.push(sheet)
    saveStore()
  }

  const regs = store.courseRegistrations.filter((r) => r.courseId === courseId && ['registered', 'pending'].includes(r.status))
  const students = regs.map((r) => {
    const user = store.users.find((u) => u.id === r.studentId)
    const entry = store.gradeEntries.find((g) => g.gradeSheetId === sheet.id && g.studentId === r.studentId)
    const marks = entry || { catMarks: null, assignmentMarks: null, examMarks: null, total: null, grade: null }
    return {
      studentId: r.studentId,
      studentName: user?.name || `Student ${r.studentId}`,
      registrationStatus: r.status,
      ...marks
    }
  })
  res.json({ semester, semesterLocked, course, sheet, students, policy: store.gradingPolicy })
})

app.post('/api/lecturer/grade-entry/:courseId/save-draft', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const courseId = Number(req.params.courseId)
  const rows = Array.isArray(req.body.rows) ? req.body.rows : []
  const semester = getCurrentSemesterForGrading()
  if (!semester) return res.status(400).json({ error: 'No semester configured' })
  if (semester.gradesLocked) return res.status(400).json({ error: 'Semester grades are locked' })
  const sheet = store.gradeSheets.find((s) => s.courseId === courseId && s.semesterId === semester.id)
  if (!sheet) return res.status(404).json({ error: 'Grade sheet not found' })
  if (sheet.status === 'submitted' || sheet.status === 'approved') return res.status(400).json({ error: 'Sheet is locked after submission' })

  rows.forEach((r) => {
    const studentId = Number(r.studentId)
    let entry = store.gradeEntries.find((e) => e.gradeSheetId === sheet.id && e.studentId === studentId)
    const catMarks = Number(r.catMarks ?? 0)
    const assignmentMarks = Number(r.assignmentMarks ?? 0)
    const examMarks = Number(r.examMarks ?? 0)
    const safeCat = Number.isFinite(catMarks) ? Math.max(0, Math.min(100, catMarks)) : 0
    const safeAssignment = Number.isFinite(assignmentMarks) ? Math.max(0, Math.min(100, assignmentMarks)) : 0
    const safeExam = Number.isFinite(examMarks) ? Math.max(0, Math.min(100, examMarks)) : 0
    const catComposite = Number((safeCat + safeAssignment).toFixed(2))
    const computed = computeFinalMark(catComposite, safeExam)
    if (!entry) {
      entry = {
        id: nextId('gradeEntries'),
        gradeSheetId: sheet.id,
        studentId,
        catMarks: safeCat,
        assignmentMarks: safeAssignment,
        examMarks: safeExam,
        total: computed.finalScore,
        grade: computed.letter,
        createdAt: nowIso(),
        updatedAt: nowIso()
      }
      store.gradeEntries.push(entry)
    } else {
      entry.catMarks = safeCat
      entry.assignmentMarks = safeAssignment
      entry.examMarks = safeExam
      entry.total = computed.finalScore
      entry.grade = computed.letter
      entry.updatedAt = nowIso()
    }
  })
  sheet.status = 'draft'
  sheet.updatedAt = nowIso()
  saveStore()
  logActivity(req.user.id, 'lecturer.grades.save-draft', { courseId, semesterId: semester.id, count: rows.length })
  res.json({ ok: true, sheetId: sheet.id, status: sheet.status })
})

app.post('/api/lecturer/grade-entry/:courseId/submit', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const courseId = Number(req.params.courseId)
  const semester = getCurrentSemesterForGrading()
  if (!semester) return res.status(400).json({ error: 'No semester configured' })
  if (semester.gradesLocked) return res.status(400).json({ error: 'Semester grades are locked' })
  const sheet = store.gradeSheets.find((s) => s.courseId === courseId && s.semesterId === semester.id)
  if (!sheet) return res.status(404).json({ error: 'Grade sheet not found' })
  if (sheet.status === 'approved') return res.status(400).json({ error: 'Already approved' })
  const regs = store.courseRegistrations.filter((r) => r.courseId === courseId && ['registered', 'pending'].includes(r.status))
  const missing = regs.filter((r) => {
    const e = store.gradeEntries.find((g) => g.gradeSheetId === sheet.id && g.studentId === r.studentId)
    return !e || e.examMarks === null || e.examMarks === undefined
  })
  if (missing.length) return res.status(400).json({ error: `Cannot submit. ${missing.length} student(s) missing marks.` })
  sheet.status = 'submitted'
  sheet.submittedBy = req.user.id
  sheet.submittedAt = nowIso()
  sheet.updatedAt = nowIso()
  saveStore()
  logActivity(req.user.id, 'lecturer.grades.submit', { courseId, semesterId: semester.id, sheetId: sheet.id })
  res.json({ ok: true, sheet })
})

app.get('/api/admin/grades/pending', auth, requireRole(['admin']), (_req, res) => {
  const pending = store.gradeSheets
    .filter((s) => s.status === 'submitted')
    .map((s) => {
      const entries = store.gradeEntries.filter((e) => e.gradeSheetId === s.id)
      const dist = { A: 0, B: 0, C: 0, D: 0, F: 0 }
      entries.forEach((e) => { if (dist[e.grade] !== undefined) dist[e.grade] += 1 })
      const course = store.hierarchyCourses.find((c) => c.id === s.courseId) || store.courses.find((c) => c.id === s.courseId)
      const lecturer = store.users.find((u) => u.id === s.lecturerId)
      return {
        sheetId: s.id,
        courseId: s.courseId,
        courseCode: course?.code || '-',
        courseTitle: course?.title || '-',
        lecturer: lecturer?.name || '-',
        students: entries.length,
        distribution: dist,
        submittedAt: s.submittedAt
      }
    })
  res.json(pending)
})

app.get('/api/admin/grades/all', auth, requireRole(['admin']), (_req, res) => {
  const rows = store.results.map((r) => {
    const student = store.users.find((u) => u.id === r.studentId)
    const course = store.hierarchyCourses.find((c) => c.id === r.courseId) || store.courses.find((c) => c.id === r.courseId)
    const program = store.hierarchyPrograms.find((p) => p.id === course?.programId)
    const dept = store.hierarchyDepartments.find((d) => d.id === program?.departmentId)
    return {
      ...r,
      studentName: student?.name || '-',
      courseCode: course?.code || '-',
      courseTitle: course?.title || '-',
      departmentName: dept?.name || '-'
    }
  })
  res.json(rows)
})

app.post('/api/admin/grades/:sheetId/approve', auth, requireRole(['admin']), (req, res) => {
  const sheet = store.gradeSheets.find((s) => s.id === Number(req.params.sheetId))
  if (!sheet) return res.status(404).json({ error: 'Grade sheet not found' })
  if (sheet.status !== 'submitted') return res.status(400).json({ error: 'Only submitted sheets can be approved' })
  const semester = store.hierarchySemesters.find((s) => s.id === sheet.semesterId)
  if (semester?.gradesLocked) return res.status(400).json({ error: 'Semester grades are locked' })
  const entries = store.gradeEntries.filter((e) => e.gradeSheetId === sheet.id)
  entries.forEach((entry) => {
    const existing = store.results.find((r) => r.studentId === entry.studentId && r.courseId === sheet.courseId && r.semesterId === sheet.semesterId)
    const payload = {
      studentId: entry.studentId,
      courseId: sheet.courseId,
      semesterId: sheet.semesterId,
      score: entry.total,
      grade: entry.grade,
      approved: true,
      semesterCode: semester?.name || ''
    }
    if (existing) Object.assign(existing, payload)
    else store.results.push({ id: nextId('results'), ...payload })
  })
  sheet.status = 'approved'
  sheet.approvedBy = req.user.id
  sheet.approvedAt = nowIso()
  sheet.updatedAt = nowIso()
  saveStore()
  logActivity(req.user.id, 'admin.grades.approve', { sheetId: sheet.id, courseId: sheet.courseId })
  res.json({ ok: true, sheet })
})

app.post('/api/admin/grades/:sheetId/reject', auth, requireRole(['admin']), (req, res) => {
  const sheet = store.gradeSheets.find((s) => s.id === Number(req.params.sheetId))
  if (!sheet) return res.status(404).json({ error: 'Grade sheet not found' })
  if (sheet.status !== 'submitted') return res.status(400).json({ error: 'Only submitted sheets can be rejected' })
  sheet.status = 'rejected'
  sheet.rejectComment = req.body.comment || 'Please correct the grade sheet and resubmit.'
  sheet.rejectedBy = req.user.id
  sheet.rejectedAt = nowIso()
  sheet.updatedAt = nowIso()
  saveStore()
  logActivity(req.user.id, 'admin.grades.reject', { sheetId: sheet.id })
  res.json({ ok: true, sheet })
})

app.post('/api/admin/grades/semester-control', auth, requireRole(['admin']), (req, res) => {
  const semesterId = Number(req.body.semesterId)
  const semester = store.hierarchySemesters.find((s) => s.id === semesterId)
  if (!semester) return res.status(404).json({ error: 'Semester not found' })
  if (req.body.gradesLocked !== undefined) semester.gradesLocked = Boolean(req.body.gradesLocked)
  if (req.body.resultsPublished !== undefined) semester.resultsPublished = Boolean(req.body.resultsPublished)
  if (req.body.attendanceLocked !== undefined) semester.attendanceLocked = Boolean(req.body.attendanceLocked)
  saveStore()
  logActivity(req.user.id, 'admin.grades.semester-control', {
    semesterId,
    gradesLocked: semester.gradesLocked,
    resultsPublished: semester.resultsPublished,
    attendanceLocked: semester.attendanceLocked
  })
  res.json(semester)
})

app.get('/api/admin/grades/analytics', auth, requireRole(['admin']), (_req, res) => {
  const approved = store.results.filter((r) => r.approved === true)
  const passCount = approved.filter((r) => ['A', 'B', 'C', 'D'].includes(r.grade)).length
  const failCount = approved.filter((r) => r.grade === 'F').length
  const total = approved.length || 1
  const passRate = Number(((passCount / total) * 100).toFixed(2))

  const students = store.students.map((s) => {
    const result = buildStudentResults(s.userId)
    return {
      userId: s.userId,
      registrationNumber: s.registrationNumber,
      gpa: Number(result.cgpa || 0),
      name: store.users.find((u) => u.id === s.userId)?.name || `Student ${s.userId}`
    }
  })
  const top10 = students.slice().sort((a, b) => b.gpa - a.gpa).slice(0, 10)
  const warning = students.filter((s) => s.gpa > 0 && s.gpa < 2.0)
  const distribution = {
    '0.0-0.99': students.filter((s) => s.gpa >= 0 && s.gpa < 1).length,
    '1.0-1.99': students.filter((s) => s.gpa >= 1 && s.gpa < 2).length,
    '2.0-2.99': students.filter((s) => s.gpa >= 2 && s.gpa < 3).length,
    '3.0-4.0': students.filter((s) => s.gpa >= 3).length
  }

  const passFailByDepartment = store.hierarchyDepartments.map((d) => {
    const programIds = store.hierarchyPrograms.filter((p) => p.departmentId === d.id).map((p) => p.id)
    const courseIds = store.hierarchyCourses.filter((c) => programIds.includes(c.programId)).map((c) => c.id)
    const deptResults = approved.filter((r) => courseIds.includes(r.courseId))
    const pass = deptResults.filter((r) => ['A', 'B', 'C', 'D'].includes(r.grade)).length
    const fail = deptResults.filter((r) => r.grade === 'F').length
    return { department: d.name, pass, fail }
  })

  res.json({
    passRate,
    passCount,
    failCount,
    totalRecords: approved.length,
    top10Students: top10,
    academicWarning: warning,
    gpaDistribution: distribution,
    passFailByDepartment
  })
})

app.post('/api/lecturer/marks', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const { studentId, courseId, score } = req.body
  const numericScore = Number(score)
  if (Number.isNaN(numericScore) || numericScore < 0 || numericScore > 100) {
    return res.status(400).json({ error: 'Score must be between 0 and 100' })
  }
  const semester = getCurrentSemesterForGrading()
  if (!semester) return res.status(400).json({ error: 'No semester configured' })
  if (semester.gradesLocked) return res.status(400).json({ error: 'Semester grades are locked' })
  const grade = gradeFromScore(numericScore)

  if (STORAGE_ENGINE === 'prisma') {
    Promise.all([
      prisma.user.findUnique({ where: { id: Number(studentId) } }),
      prisma.course.findUnique({ where: { id: Number(courseId) } }),
      latestSemesterData()
    ]).then(([student, course, semester]) => {
      if (!student || roleFromDb(student.role) !== 'student' || !course || !semester) {
        return res.status(404).json({ error: 'Student or course/semester not found' })
      }
      return prisma.result.upsert({
        where: {
          studentId_courseId_semesterId: {
            studentId: student.id,
            courseId: course.id,
            semesterId: semester.id
          }
        },
        update: {
          score: numericScore,
          grade,
          approved: false
        },
        create: {
          studentId: student.id,
          courseId: course.id,
          semesterId: semester.id,
          score: numericScore,
          grade,
          approved: false
        }
      }).then((row) => {
        logActivity(req.user.id, 'lecturer.mark.enter', { studentId: student.id, courseId: course.id, score: numericScore })
        res.json(row)
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to enter marks' })
    })
    return
  }

  const student = store.users.find((u) => u.id === Number(studentId) && u.role === 'student')
  const course = store.courses.find((c) => c.id === Number(courseId))
  if (!student || !course) return res.status(404).json({ error: 'Student or course not found' })

  let row = store.results.find((r) => r.studentId === student.id && r.courseId === course.id && Number(r.semesterId || semester.id) === semester.id)
  if (!row) {
    row = {
      id: nextId('results'),
      studentId: student.id,
      courseId: course.id,
      semesterId: semester.id,
      score: numericScore,
      grade,
      semesterCode: semester.name || 'N/A',
      approved: false
    }
    store.results.push(row)
  } else {
    row.score = numericScore
    row.grade = grade
    row.approved = false
  }

  saveStore()
  logActivity(req.user.id, 'lecturer.mark.enter', { studentId: student.id, courseId: course.id, score: numericScore })
  res.json(row)
})

app.get('/api/lecturer/class-list/:courseId', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const courseId = Number(req.params.courseId)
  if (STORAGE_ENGINE === 'prisma') {
    prisma.courseRegistration.findMany({
      where: { courseId, status: 'registered' },
      include: { student: true }
    }).then((rows) => {
      const students = rows.map((r) => ({ id: r.student.id, name: r.student.name, email: r.student.email }))
      res.json(students)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load class list' })
    })
    return
  }
  const students = store.courseRegistrations
    .filter((r) => r.courseId === courseId && r.status === 'registered')
    .map((r) => store.users.find((u) => u.id === r.studentId))
    .filter(Boolean)
    .map((u) => ({ id: u.id, name: u.name, email: u.email }))
  res.json(students)
})

app.get('/api/finance/fee-structure', auth, requireAnyPermission(['finance.view', 'finance.self', 'academic.view']), (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.feeStructure.findMany({ orderBy: { id: 'asc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load fee structures' })
      })
    return
  }
  res.json(store.feeStructures)
})

app.post('/api/finance/fee-structure', auth, requireAnyPermission(['finance.manage', 'academic.manage']), (req, res) => {
  const { level, tuitionPerSemester, upkeepPerSemester, currency = 'KES' } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.feeStructure.create({
      data: {
        level: level || 'General',
        tuitionPerSemester: Number(tuitionPerSemester) || 0,
        upkeepPerSemester: Number(upkeepPerSemester) || 0,
        currency
      }
    }).then((record) => {
      logActivity(req.user.id, 'finance.structure.create', { level: record.level })
      res.status(201).json(record)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create fee structure' })
    })
    return
  }
  const record = {
    id: nextId('feeStructures'),
    level: level || 'General',
    tuitionPerSemester: Number(tuitionPerSemester) || 0,
    upkeepPerSemester: Number(upkeepPerSemester) || 0,
    currency
  }
  store.feeStructures.push(record)
  saveStore()
  logActivity(req.user.id, 'finance.structure.create', { level: record.level })
  res.status(201).json(record)
})

app.get('/api/finance/balance', auth, requireRole(['student']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    ensureFinanceAccountData(req.user.id)
      .then((account) => res.json(account))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load fee balance' })
      })
    return
  }
  res.json(ensureFinanceAccount(req.user.id))
})

app.post('/api/finance/payments', auth, requireRole(['student']), (req, res) => {
  const { amount, method = 'card', target = 'tuition', reference } = req.body
  const numericAmount = Number(amount)
  if (Number.isNaN(numericAmount) || numericAmount <= 0) {
    return res.status(400).json({ error: 'Valid amount is required' })
  }
  if (!['mpesa', 'bank', 'card'].includes(method)) {
    return res.status(400).json({ error: 'method must be mpesa|bank|card' })
  }

  if (STORAGE_ENGINE === 'prisma') {
    const methodDb = paymentMethodToDb(method)
    const targetDb = paymentTargetToDb(target)
    ensureFinanceAccountData(req.user.id).then(async (account) => {
      const payment = await prisma.payment.create({
        data: {
          studentId: req.user.id,
          amount: numericAmount,
          method: methodDb,
          target: targetDb,
          reference: reference || `${String(method).toUpperCase()}-${Date.now()}`
        }
      })
      const updated = await prisma.financeAccount.update({
        where: { studentId: req.user.id },
        data: targetDb === 'UPKEEP'
          ? { upkeepBalance: Math.max(0, account.upkeepBalance - numericAmount) }
          : { tuitionBalance: Math.max(0, account.tuitionBalance - numericAmount) }
      })
      logActivity(req.user.id, 'finance.payment', { amount: numericAmount, method, target })
      res.status(201).json({ payment, balance: updated })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to process payment' })
    })
    return
  }

  const payment = {
    id: nextId('payments'),
    studentId: req.user.id,
    amount: numericAmount,
    method,
    target,
    reference: reference || `${method.toUpperCase()}-${Date.now()}`,
    paidAt: nowIso()
  }
  store.payments.push(payment)

  const account = ensureFinanceAccount(req.user.id)
  if (target === 'upkeep') account.upkeepBalance = Math.max(0, account.upkeepBalance - numericAmount)
  else account.tuitionBalance = Math.max(0, account.tuitionBalance - numericAmount)
  account.updatedAt = nowIso()

  saveStore()
  logActivity(req.user.id, 'finance.payment', { amount: numericAmount, method, target })
  res.status(201).json({ payment, balance: account })
})

app.get('/api/finance/statement', auth, requireRole(['student']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    Promise.all([
      prisma.payment.findMany({ where: { studentId: req.user.id }, orderBy: { paidAt: 'desc' } }),
      ensureFinanceAccountData(req.user.id)
    ]).then(([payments, balance]) => {
      res.json({
        studentId: req.user.id,
        generatedAt: nowIso(),
        payments,
        balance
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to generate statement' })
    })
    return
  }
  const payments = store.payments.filter((p) => p.studentId === req.user.id)
  const balance = ensureFinanceAccount(req.user.id)
  res.json({
    studentId: req.user.id,
    generatedAt: nowIso(),
    payments,
    balance
  })
})

app.get('/api/communications/announcements', auth, (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.announcement.findMany({ orderBy: { createdAt: 'desc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load announcements' })
      })
    return
  }
  res.json([...store.announcements].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)))
})

app.post('/api/communications/announcements', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const { title, body, audience = 'all' } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.announcement.create({
      data: {
        title: title || 'Announcement',
        body: body || '',
        audience,
        authorId: req.user.id
      }
    }).then((row) => {
      logActivity(req.user.id, 'communication.announcement.create', { announcementId: row.id })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create announcement' })
    })
    return
  }
  const row = {
    id: nextId('announcements'),
    title: title || 'Announcement',
    body: body || '',
    audience,
    authorId: req.user.id,
    createdAt: nowIso()
  }
  store.announcements.push(row)
  saveStore()
  logActivity(req.user.id, 'communication.announcement.create', { announcementId: row.id })
  res.status(201).json(row)
})

app.get('/api/communications/messages', auth, (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.message.findMany({
      where: { OR: [{ toUserId: req.user.id }, { fromUserId: req.user.id }] },
      orderBy: { createdAt: 'desc' }
    }).then((rows) => res.json(rows)).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load messages' })
    })
    return
  }
  const rows = store.messages.filter((m) => m.toUserId === req.user.id || m.fromUserId === req.user.id)
  res.json(rows)
})

app.get('/api/finance/invoices', auth, requireAnyPermission(['finance.view', 'finance.manage']), (req, res) => {
  const rows = store.invoices.map((inv) => ({
    ...inv,
    studentName: store.users.find((u) => u.id === inv.studentId)?.name || '-'
  }))
  res.json(rows)
})

app.post('/api/finance/invoices', auth, requireAnyPermission(['finance.manage']), (req, res) => {
  const { studentId, semesterId, amount, description } = req.body
  const student = store.users.find((u) => u.id === Number(studentId))
  if (!student) return res.status(404).json({ error: 'Student not found' })
  const row = {
    id: nextId('invoices'),
    studentId: Number(studentId),
    semesterId: Number(semesterId || getCurrentSemesterForGrading()?.id || 0),
    amount: Number(amount || 0),
    description: description || 'Invoice',
    status: 'unpaid',
    createdAt: nowIso()
  }
  store.invoices.push(row)
  const account = ensureFinanceAccount(row.studentId)
  account.tuitionBalance = Number(account.tuitionBalance || 0) + row.amount
  account.updatedAt = nowIso()
  saveStore()
  logActivity(req.user.id, 'finance.invoice.create', { invoiceId: row.id, studentId: row.studentId })
  res.status(201).json(row)
})

app.patch('/api/finance/invoices/:id/pay', auth, requireAnyPermission(['finance.manage']), (req, res) => {
  const row = store.invoices.find((i) => i.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Invoice not found' })
  if (row.status === 'paid') return res.status(400).json({ error: 'Invoice already paid' })
  row.status = 'paid'
  row.paidAt = nowIso()
  const account = ensureFinanceAccount(row.studentId)
  account.tuitionBalance = Math.max(0, Number(account.tuitionBalance || 0) - Number(row.amount || 0))
  account.updatedAt = nowIso()
  const payment = {
    id: nextId('payments'),
    studentId: row.studentId,
    amount: Number(row.amount || 0),
    method: String(req.body.method || 'bank').toLowerCase(),
    target: 'tuition',
    reference: req.body.reference || `INV-${row.id}-${Date.now()}`,
    createdAt: nowIso()
  }
  store.payments.push(payment)
  saveStore()
  logActivity(req.user.id, 'finance.invoice.pay', { invoiceId: row.id, paymentId: payment.id })
  res.json({ invoice: row, payment })
})

app.get('/api/finance/receipts/:paymentId', auth, requireAnyPermission(['finance.view', 'finance.manage', 'finance.self']), (req, res) => {
  const payment = store.payments.find((p) => p.id === Number(req.params.paymentId))
  if (!payment) return res.status(404).json({ error: 'Payment not found' })
  if (!hasPermission(req.user, 'finance.view') && req.user.id !== payment.studentId) return res.status(403).json({ error: 'Forbidden' })
  const student = store.users.find((u) => u.id === payment.studentId)
  const inst = getInstitutionSettings()
  res.json({
    receiptNo: `RCP-${payment.id}`,
    institutionName: inst.institutionName,
    logo: inst.mainLogo,
    student: { id: student?.id, name: student?.name, email: student?.email },
    payment
  })
})

app.get('/api/finance/revenue-dashboard', auth, requireAnyPermission(['finance.view', 'finance.manage', 'reports.view']), (_req, res) => {
  const totalRevenue = store.payments.reduce((sum, p) => sum + Number(p.amount || 0), 0)
  const pendingBalances = store.financeAccounts.reduce((sum, a) => sum + Number(a.tuitionBalance || 0) + Number(a.upkeepBalance || 0), 0)
  const monthly = {}
  store.payments.forEach((p) => {
    const m = String((p.createdAt || nowIso())).slice(0, 7)
    monthly[m] = Number((monthly[m] || 0) + Number(p.amount || 0))
  })
  const paid = store.invoices.filter((i) => i.status === 'paid').length
  const unpaid = store.invoices.filter((i) => i.status !== 'paid').length
  res.json({
    totalRevenue,
    pendingBalances,
    monthlyIncomeTrend: Object.entries(monthly).map(([month, amount]) => ({ month, amount })),
    paidVsUnpaid: { paid, unpaid }
  })
})

app.post('/api/communications/messages', auth, (req, res) => {
  const { toUserId, body } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.user.findUnique({ where: { id: Number(toUserId) } }).then((to) => {
      if (!to) return res.status(404).json({ error: 'Recipient not found' })
      return prisma.message.create({
        data: {
          fromUserId: req.user.id,
          toUserId: to.id,
          body: body || ''
        }
      }).then((row) => {
        logActivity(req.user.id, 'communication.message.send', { toUserId: to.id })
        res.status(201).json(row)
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to send message' })
    })
    return
  }
  const to = store.users.find((u) => u.id === Number(toUserId))
  if (!to) return res.status(404).json({ error: 'Recipient not found' })

  const row = {
    id: nextId('messages'),
    fromUserId: req.user.id,
    toUserId: to.id,
    body: body || '',
    createdAt: nowIso()
  }
  store.messages.push(row)
  saveStore()
  logActivity(req.user.id, 'communication.message.send', { toUserId: to.id })
  res.status(201).json(row)
})

app.get('/api/communications/notifications', auth, (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    const where = req.user.role === 'admin'
      ? {}
      : { OR: [{ toUserId: req.user.id }, { audience: 'all' }] }
    prisma.notification.findMany({ where, orderBy: { createdAt: 'desc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load notifications' })
      })
    return
  }
  if (req.user.role === 'admin') return res.json(store.notifications)
  const rows = store.notifications.filter((n) => n.toUserId === req.user.id || n.audience === 'all')
  return res.json(rows)
})

app.post('/api/communications/notifications', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const { channel = 'email', toUserId, message, audience = 'targeted' } = req.body
  if (!['email', 'sms'].includes(channel)) {
    return res.status(400).json({ error: 'channel must be email|sms' })
  }
  if (!message) return res.status(400).json({ error: 'message is required' })
  if (channel === 'sms') {
    return res.status(501).json({ error: 'SMS delivery not configured. Use email or configure an SMS provider.' })
  }

  if (STORAGE_ENGINE === 'prisma') {
    const channelDb = String(channel).toLowerCase() === 'sms' ? 'SMS' : 'EMAIL'
    const targetId = audience === 'all' ? null : Number(toUserId)
    const afterRecipientCheck = () => prisma.notification.create({
      data: {
        channel: channelDb,
        audience,
        toUserId: targetId,
        message,
        status: 'queued',
        sentById: req.user.id
      }
    }).then(async (row) => {
      try {
        if (channelDb === 'EMAIL') {
          await sendNotificationEmail({ audience, toUserId: targetId, message })
          await prisma.notification.update({ where: { id: row.id }, data: { status: 'sent' } })
          row.status = 'sent'
        }
        logActivity(req.user.id, 'communication.notification.send', { notificationId: row.id, channel, audience })
        return res.status(201).json(row)
      } catch (error) {
        console.error('notification send failed', error)
        await prisma.notification.update({ where: { id: row.id }, data: { status: 'failed' } })
        return res.status(500).json({ error: 'Failed to send notification email.' })
      }
    })
    if (audience !== 'all') {
      prisma.user.findUnique({ where: { id: targetId } }).then((user) => {
        if (!user) return res.status(404).json({ error: 'Recipient not found' })
        return afterRecipientCheck()
      }).catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to send notification' })
      })
      return
    }
    afterRecipientCheck().catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to send notification' })
    })
    return
  }

  if (audience !== 'all' && !store.users.find((u) => u.id === Number(toUserId))) {
    return res.status(404).json({ error: 'Recipient not found' })
  }

  const row = {
    id: nextId('notifications'),
    channel,
    audience,
    toUserId: audience === 'all' ? null : Number(toUserId),
    message,
    status: 'queued',
    sentBy: req.user.id,
    createdAt: nowIso()
  }
  store.notifications.push(row)
  saveStore()
  if (channel === 'email') {
    sendNotificationEmail({ audience, toUserId: row.toUserId, message })
      .then(() => {
        row.status = 'sent'
        saveStore()
        logActivity(req.user.id, 'communication.notification.send', { notificationId: row.id, channel, audience })
        return res.status(201).json(row)
      })
      .catch((error) => {
        console.error('notification send failed', error)
        row.status = 'failed'
        saveStore()
        return res.status(500).json({ error: 'Failed to send notification email.' })
      })
    return
  }
  logActivity(req.user.id, 'communication.notification.send', { notificationId: row.id, channel, audience })
  return res.status(201).json(row)
})

app.get('/api/admin/departments', auth, requireRole(['admin']), (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.department.findMany({ orderBy: { id: 'asc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load departments' })
      })
    return
  }
  res.json(store.departments)
})

app.post('/api/admin/departments', auth, requireRole(['admin']), (req, res) => {
  const { name, code } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.department.create({
      data: { name, code }
    }).then((row) => {
      logActivity(req.user.id, 'admin.department.create', { departmentId: row.id })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create department' })
    })
    return
  }
  const row = { id: nextId('departments'), name, code }
  store.departments.push(row)
  saveStore()
  logActivity(req.user.id, 'admin.department.create', { departmentId: row.id })
  res.status(201).json(row)
})

app.post('/api/admin/programs', auth, requireRole(['admin']), (req, res) => {
  const { name, code, departmentId } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.program.create({
      data: { name, code, departmentId: Number(departmentId) }
    }).then((row) => {
      logActivity(req.user.id, 'admin.program.create', { programId: row.id })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create program' })
    })
    return
  }
  const row = { id: nextId('programs'), name, code, departmentId: Number(departmentId) }
  store.programs.push(row)
  saveStore()
  logActivity(req.user.id, 'admin.program.create', { programId: row.id })
  res.status(201).json(row)
})

app.post('/api/admin/semesters', auth, requireRole(['admin']), (req, res) => {
  const { name, code, startDate, endDate } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.semester.create({
      data: { name, code, startDate: new Date(startDate), endDate: new Date(endDate) }
    }).then((row) => {
      logActivity(req.user.id, 'admin.semester.create', { semesterId: row.id })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create semester' })
    })
    return
  }
  const row = { id: nextId('semesters'), name, code, startDate, endDate }
  store.semesters.push(row)
  saveStore()
  logActivity(req.user.id, 'admin.semester.create', { semesterId: row.id })
  res.status(201).json(row)
})

app.post('/api/admin/courses', auth, requireRole(['admin']), (req, res) => {
  const { code, title, credits = 3, lecturerId, semesterId, departmentId } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.course.create({
      data: {
        code,
        title,
        credits: Number(credits),
        lecturerId: Number(lecturerId),
        semesterId: Number(semesterId),
        departmentId: Number(departmentId)
      }
    }).then((row) => {
      logActivity(req.user.id, 'admin.course.create', { courseId: row.id })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create course' })
    })
    return
  }
  const row = {
    id: nextId('courses'),
    code,
    title,
    credits: Number(credits),
    lecturerId: Number(lecturerId),
    semesterId: Number(semesterId),
    departmentId: Number(departmentId)
  }
  store.courses.push(row)
  saveStore()
  logActivity(req.user.id, 'admin.course.create', { courseId: row.id })
  res.status(201).json(row)
})

app.get('/api/admin/staff', auth, requireRole(['admin']), (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.user.findMany({
      where: { role: { in: ['LECTURER', 'STAFF', 'ADMIN'] } },
      select: { id: true, name: true, email: true, role: true },
      orderBy: { id: 'asc' }
    }).then((rows) => {
      res.json(rows.map((u) => ({ ...u, role: roleFromDb(u.role) })))
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load staff list' })
    })
    return
  }
  const rows = store.users
    .filter((u) => u.role === 'lecturer' || u.role === 'admin')
    .map((u) => ({ id: u.id, name: u.name, email: u.email, role: u.role }))
  res.json(rows)
})

app.post('/api/admin/staff', auth, requireRole(['admin']), async (req, res) => {
  const {
    name,
    email,
    role = 'lecturer',
    password = '',
    username = '',
    personNumber = '',
    phone = '',
    autoGeneratePassword = false,
    mustChangePassword: mustChangePasswordRequested
  } = req.body
  if (!email || !name) return res.status(400).json({ error: 'name and email are required' })
  const accessRole = normalizeRoleName(role)
  if (!RBAC_ROLES.includes(accessRole)) return res.status(400).json({ error: `role must be one of: ${RBAC_ROLES.join(', ')}` })
  const generatedNumber = personNumber || `STF${new Date().getFullYear()}${String(nextId('users')).padStart(3, '0')}`
  const generatedUsername = ensureUniqueUsername(username || generateUsername(name, generatedNumber))
  const plainPassword = autoGeneratePassword ? generateTemporaryPassword(12) : String(password || '')
  if (!plainPassword || plainPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters (or use auto-generate).' })
  const mustChangePassword = mustChangePasswordRequested !== undefined ? Boolean(mustChangePasswordRequested) : Boolean(autoGeneratePassword)
  if (STORAGE_ENGINE === 'prisma') {
    const existing = await prisma.user.findUnique({ where: { email } })
    if (existing) return res.status(409).json({ error: 'Email already used' })
    const row = await prisma.user.create({
      data: {
        name,
        email,
        role: roleToDb(accessRole),
        password: await bcrypt.hash(plainPassword, 10),
        twoFactorEnabled: false
      }
    })
    store.userRoleAssignments = (store.userRoleAssignments || []).filter((a) => a.userId !== row.id)
    store.userRoleAssignments.push({ userId: row.id, accessRole, updatedAt: nowIso() })
    upsertAccountProfile(row.id, {
      username: generatedUsername,
      personNumber: generatedNumber,
      phone,
      mustChangePassword
    })
    saveStore()
    logActivity(req.user.id, 'admin.staff.create', { staffId: row.id, role: accessRole })
    try {
      await sendTemporaryPasswordEmail(email, generatedUsername, plainPassword)
    } catch (error) {
      console.error('staff credentials email failed', error)
      return res.status(500).json({ error: 'Failed to send credentials email. Check email configuration and try again.' })
    }
    return res.status(201).json(userPublicView(row))
  }
  if (store.users.find((u) => u.email === email)) return res.status(409).json({ error: 'Email already used' })

  const row = {
    id: nextId('users'),
    name,
    email,
    role: dbRoleForAccessRole(accessRole),
    password: await bcrypt.hash(plainPassword, 10),
    twoFactorEnabled: false
  }
  store.users.push(row)
  store.userRoleAssignments.push({ userId: row.id, accessRole, updatedAt: nowIso() })
  upsertAccountProfile(row.id, {
    username: generatedUsername,
    personNumber: generatedNumber,
    phone,
    mustChangePassword
  })
  saveStore()
  logActivity(req.user.id, 'admin.staff.create', { staffId: row.id, role: accessRole })
  try {
    await sendTemporaryPasswordEmail(email, generatedUsername, plainPassword)
  } catch (error) {
    console.error('staff credentials email failed', error)
    return res.status(500).json({ error: 'Failed to send credentials email. Check email configuration and try again.' })
  }
  res.status(201).json(userPublicView(row))
})

app.get('/api/admin/users', auth, requireRole(['admin']), (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.user.findMany({
      select: { id: true, name: true, email: true, role: true, twoFactorEnabled: true },
      orderBy: { id: 'asc' }
    }).then((users) => {
      res.json(users.map((u) => userPublicView(u)))
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load users' })
    })
    return
  }
  const rows = store.users.map((u) => userPublicView(u))
  res.json(rows)
})

app.post('/api/admin/users', auth, requireRole(['admin']), async (req, res) => {
  const {
    name,
    email,
    role = 'student',
    password = '',
    username = '',
    phone = '',
    personNumber = '',
    autoGenerateUsername = true,
    autoGeneratePassword = false,
    mustChangePassword: mustChangePasswordRequested,
    programId = null,
    departmentId = null
  } = req.body
  if (!name || !email) return res.status(400).json({ error: 'name and email are required' })
  const accessRole = normalizeRoleName(role)
  if (!RBAC_ROLES.includes(accessRole)) {
    return res.status(400).json({ error: `role must be one of: ${RBAC_ROLES.join(', ')}` })
  }
  const derivedNumber = personNumber || (accessRole === 'student'
    ? `STD${new Date().getFullYear()}${String(nextId('users')).padStart(3, '0')}`
    : `STF${new Date().getFullYear()}${String(nextId('users')).padStart(3, '0')}`)
  const generatedUsername = ensureUniqueUsername(autoGenerateUsername ? generateUsername(name, derivedNumber) : (username || generateUsername(name, derivedNumber)))
  const plainPassword = autoGeneratePassword ? generateTemporaryPassword(12) : String(password || '')
  if (!plainPassword || plainPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters (or use auto-generate).' })
  const mustChangePassword = mustChangePasswordRequested !== undefined ? Boolean(mustChangePasswordRequested) : Boolean(autoGeneratePassword)
  if (STORAGE_ENGINE === 'prisma') {
    const existing = await prisma.user.findUnique({ where: { email } })
    if (existing) return res.status(409).json({ error: 'Email already used' })

    const row = await prisma.user.create({
      data: {
        name,
        email,
        role: roleToDb(accessRole),
        password: await bcrypt.hash(plainPassword, 10),
        twoFactorEnabled: false
      }
    })
    store.userRoleAssignments = (store.userRoleAssignments || []).filter((a) => a.userId !== row.id)
    store.userRoleAssignments.push({ userId: row.id, accessRole, updatedAt: nowIso() })
    upsertAccountProfile(row.id, {
      username: generatedUsername,
      personNumber: derivedNumber,
      phone,
      programId: programId ? Number(programId) : null,
      departmentId: departmentId ? Number(departmentId) : null,
      mustChangePassword
    })
    store.notifications.push({
      id: nextId('notifications'),
      channel: 'email',
      audience: 'targeted',
      toUserId: row.id,
      message: `Your Tech Hub account is ready. Username: ${generatedUsername}. Temporary password issued. Change password on first login.`,
      status: 'queued',
      sentBy: req.user.id,
      createdAt: nowIso()
    })
    saveStore()
    logActivity(req.user.id, 'admin.user.create', { userId: row.id, role: accessRole })
    try {
      await sendTemporaryPasswordEmail(email, generatedUsername, plainPassword)
    } catch (error) {
      console.error('user credentials email failed', error)
      return res.status(500).json({ error: 'Failed to send credentials email. Check email configuration and try again.' })
    }
    return res.status(201).json(userPublicView(row))
  }
  if (store.users.find((u) => u.email === email)) return res.status(409).json({ error: 'Email already used' })

  const row = {
    id: nextId('users'),
    name,
    email,
    role: dbRoleForAccessRole(accessRole),
    password: await bcrypt.hash(plainPassword, 10),
    twoFactorEnabled: false
  }
  store.users.push(row)
  store.userRoleAssignments.push({ userId: row.id, accessRole, updatedAt: nowIso() })
  upsertAccountProfile(row.id, {
    username: generatedUsername,
    personNumber: derivedNumber,
    phone,
    programId: programId ? Number(programId) : null,
    departmentId: departmentId ? Number(departmentId) : null,
    mustChangePassword
  })
  store.notifications.push({
    id: nextId('notifications'),
    channel: 'email',
    audience: 'targeted',
    toUserId: row.id,
    message: `Your Tech Hub account is ready. Username: ${generatedUsername}. Temporary password issued. Change password on first login.`,
    status: 'queued',
    sentBy: req.user.id,
    createdAt: nowIso()
  })
  saveStore()
  logActivity(req.user.id, 'admin.user.create', { userId: row.id, role: accessRole })
  try {
    await sendTemporaryPasswordEmail(email, generatedUsername, plainPassword)
  } catch (error) {
    console.error('user credentials email failed', error)
    return res.status(500).json({ error: 'Failed to send credentials email. Check email configuration and try again.' })
  }
  res.status(201).json(userPublicView(row))
})

app.patch('/api/admin/users/:id', auth, requireRole(['admin']), async (req, res) => {
  const id = Number(req.params.id)
  const { name, email, role, password, twoFactorEnabled, username, phone, personNumber, mustChangePassword, programId, departmentId } = req.body
  const accessRole = role ? normalizeRoleName(role) : null
  if (accessRole && !RBAC_ROLES.includes(accessRole)) {
    return res.status(400).json({ error: `role must be one of: ${RBAC_ROLES.join(', ')}` })
  }
  if (STORAGE_ENGINE === 'prisma') {
    const user = await prisma.user.findUnique({ where: { id } })
    if (!user) return res.status(404).json({ error: 'User not found' })
    if (email && email !== user.email) {
      const existing = await prisma.user.findUnique({ where: { email } })
      if (existing) return res.status(409).json({ error: 'Email already used' })
    }
    const updated = await prisma.user.update({
      where: { id },
      data: {
        ...(name ? { name } : {}),
        ...(email ? { email } : {}),
        ...(accessRole ? { role: roleToDb(accessRole) } : {}),
        ...(typeof twoFactorEnabled === 'boolean' ? { twoFactorEnabled } : {}),
        ...(password ? { password: await bcrypt.hash(password, 10) } : {})
      }
    })
    if (accessRole) {
      store.userRoleAssignments = (store.userRoleAssignments || []).filter((a) => a.userId !== id)
      store.userRoleAssignments.push({ userId: id, accessRole, updatedAt: nowIso() })
    }
    const resolvedUsername = username
      ? ensureUniqueUsername(username, id)
      : (accountProfileForUser(id)?.username || ensureUniqueUsername(generateUsername(updated.name, personNumber || accountProfileForUser(id)?.personNumber), id))
    upsertAccountProfile(id, {
      username: resolvedUsername,
      phone: phone !== undefined ? phone : accountProfileForUser(id)?.phone,
      personNumber: personNumber !== undefined ? personNumber : accountProfileForUser(id)?.personNumber,
      programId: programId !== undefined ? Number(programId) : accountProfileForUser(id)?.programId,
      departmentId: departmentId !== undefined ? Number(departmentId) : accountProfileForUser(id)?.departmentId,
      mustChangePassword: mustChangePassword !== undefined ? Boolean(mustChangePassword) : accountProfileForUser(id)?.mustChangePassword
    })
    saveStore()
    logActivity(req.user.id, 'admin.user.update', { userId: updated.id })
    return res.json(userPublicView(updated))
  }

  const user = store.users.find((u) => u.id === id)
  if (!user) return res.status(404).json({ error: 'User not found' })
  if (email && email !== user.email && store.users.find((u) => u.email === email)) {
    return res.status(409).json({ error: 'Email already used' })
  }

  if (name) user.name = name
  if (email) user.email = email
  if (accessRole) {
    user.role = dbRoleForAccessRole(accessRole)
    store.userRoleAssignments = (store.userRoleAssignments || []).filter((a) => a.userId !== id)
    store.userRoleAssignments.push({ userId: id, accessRole, updatedAt: nowIso() })
  }
  if (typeof twoFactorEnabled === 'boolean') user.twoFactorEnabled = twoFactorEnabled
  if (password) user.password = await bcrypt.hash(password, 10)
  const resolvedUsername = username
    ? ensureUniqueUsername(username, id)
    : (accountProfileForUser(id)?.username || ensureUniqueUsername(generateUsername(user.name, personNumber || accountProfileForUser(id)?.personNumber), id))
  upsertAccountProfile(id, {
    username: resolvedUsername,
    phone: phone !== undefined ? phone : accountProfileForUser(id)?.phone,
    personNumber: personNumber !== undefined ? personNumber : accountProfileForUser(id)?.personNumber,
    programId: programId !== undefined ? Number(programId) : accountProfileForUser(id)?.programId,
    departmentId: departmentId !== undefined ? Number(departmentId) : accountProfileForUser(id)?.departmentId,
    mustChangePassword: mustChangePassword !== undefined ? Boolean(mustChangePassword) : accountProfileForUser(id)?.mustChangePassword
  })

  saveStore()
  logActivity(req.user.id, 'admin.user.update', { userId: user.id })
  res.json(userPublicView(user))
})

app.delete('/api/admin/users/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  if (id === req.user.id) return res.status(400).json({ error: 'Admin cannot delete own account' })
  if (STORAGE_ENGINE === 'prisma') {
    prisma.user.findUnique({ where: { id } }).then((user) => {
      if (!user) return res.status(404).json({ error: 'User not found' })
      return prisma.user.delete({ where: { id } }).then((removed) => {
        cascadeDeleteUserDataJson(removed.id)
        saveStore()
        logActivity(req.user.id, 'admin.user.delete', { userId: removed.id })
        return res.json({ ok: true, deletedUserId: removed.id })
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to delete user' })
    })
    return
  }
  const index = store.users.findIndex((u) => u.id === id)
  if (index === -1) return res.status(404).json({ error: 'User not found' })
  const [removed] = store.users.splice(index, 1)
  cascadeDeleteUserDataJson(removed.id)
  saveStore()
  logActivity(req.user.id, 'admin.user.delete', { userId: removed.id })
  res.json({ ok: true, deletedUserId: removed.id })
})

app.post('/api/admin/users/:id/reset-password', auth, requireRole(['admin']), async (req, res) => {
  const id = Number(req.params.id)
  const tempPassword = generateTemporaryPassword(12)
  const hash = await bcrypt.hash(tempPassword, 10)
  if (STORAGE_ENGINE === 'prisma') {
    const user = await prisma.user.findUnique({ where: { id } })
    if (!user) return res.status(404).json({ error: 'User not found' })
    await prisma.user.update({ where: { id }, data: { password: hash } })
    upsertAccountProfile(id, { mustChangePassword: true })
    store.notifications.push({
      id: nextId('notifications'),
      channel: 'email',
      audience: 'targeted',
      toUserId: id,
      message: `Password reset requested by admin. Use temporary password and change it immediately.`,
      status: 'queued',
      sentBy: req.user.id,
      createdAt: nowIso()
    })
    saveStore()
    logActivity(req.user.id, 'admin.user.reset-password', { userId: id })
    try {
      await sendTemporaryPasswordEmail(user.email, accountProfileForUser(id)?.username || user.email, tempPassword)
    } catch (error) {
      console.error('reset password email failed', error)
      return res.status(500).json({ error: 'Failed to send reset email. Check email configuration and try again.' })
    }
    return res.json({ ok: true, userId: id, mustChangePassword: true })
  }
  const user = store.users.find((u) => u.id === id)
  if (!user) return res.status(404).json({ error: 'User not found' })
  user.password = hash
  upsertAccountProfile(id, { mustChangePassword: true })
  store.notifications.push({
    id: nextId('notifications'),
    channel: 'email',
    audience: 'targeted',
    toUserId: id,
    message: `Password reset requested by admin. Use temporary password and change it immediately.`,
    status: 'queued',
    sentBy: req.user.id,
    createdAt: nowIso()
  })
  saveStore()
  logActivity(req.user.id, 'admin.user.reset-password', { userId: id })
  try {
    await sendTemporaryPasswordEmail(user.email, accountProfileForUser(id)?.username || user.email, tempPassword)
  } catch (error) {
    console.error('reset password email failed', error)
    return res.status(500).json({ error: 'Failed to send reset email. Check email configuration and try again.' })
  }
  res.json({ ok: true, userId: id, mustChangePassword: true })
})

app.post('/api/admissions', (req, res) => {
  const { name, email, phone, programCode, intake, documents } = req.body || {}
  if (!name || !email || !programCode) return res.status(400).json({ error: 'name, email, and programCode are required' })
  const row = {
    id: nextId('admissions'),
    name,
    email,
    phone: phone || '',
    programCode,
    intake: intake || '',
    status: 'pending',
    decisionBy: null,
    decisionAt: null,
    registrationNumber: null,
    academicYearId: getActiveAcademicYear()?.id || null,
    documents: Array.isArray(documents) ? documents : [],
    createdAt: nowIso()
  }
  store.admissions.push(row)
  saveStore()
  logActivity(null, 'public.admission.submit', { admissionId: row.id })
  res.status(201).json({ ok: true, admission: row })
})

app.get('/api/admissions/me', auth, requireRole(['student']), (req, res) => {
  const rows = store.admissions.filter((a) => String(a.email || '').toLowerCase() === String(req.user.email || '').toLowerCase())
  res.json(rows)
})

app.get('/api/admin/admissions', auth, requireRole(['admin']), (_req, res) => {
  res.json(store.admissions.slice().sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || ''))))
})

app.post('/api/admin/admissions', auth, requireRole(['admin']), (req, res) => {
  const { name, email, phone, programCode, intake } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.program.findUnique({ where: { code: programCode } }).then((program) => {
      return prisma.admission.create({
        data: {
          name,
          email,
          phone: phone || null,
          programId: program ? program.id : null,
          status: 'PENDING',
          createdById: req.user.id
        }
      }).then((row) => {
        const activeYear = getActiveAcademicYear()
        const jsonRow = {
          id: row.id,
          name,
          email,
          phone: phone || '',
          programCode: programCode || null,
          intake: intake || '',
          status: 'pending',
          decisionBy: null,
          decisionAt: null,
          registrationNumber: null,
          academicYearId: activeYear?.id || null,
          createdAt: nowIso()
        }
        if (!store.admissions.find((a) => a.id === row.id)) {
          store.admissions.push(jsonRow)
          saveStore()
        }
        logActivity(req.user.id, 'admin.admission.create', { admissionId: row.id })
        res.status(201).json(jsonRow)
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create admission' })
    })
    return
  }
  const row = {
    id: nextId('admissions'),
    name,
    email,
    phone: phone || '',
    programCode,
    programId: store.hierarchyPrograms.find((p) => p.code === programCode)?.id || null,
    intake: intake || '',
    status: 'pending',
    decisionBy: null,
    decisionAt: null,
    registrationNumber: null,
    academicYearId: getActiveAcademicYear()?.id || null,
    createdAt: nowIso()
  }
  store.admissions.push(row)
  saveStore()
  logActivity(req.user.id, 'admin.admission.create', { admissionId: row.id })
  res.status(201).json(row)
})

app.patch('/api/admin/admissions/:id', auth, requireRole(['admin']), async (req, res) => {
  const id = Number(req.params.id)
  const requestedStatus = String(req.body.status || '').toLowerCase()
  const mappedStatus = ['approved', 'rejected', 'waitlist', 'pending'].includes(requestedStatus) ? requestedStatus : 'pending'

  const row = store.admissions.find((item) => item.id === id)
  if (!row) return res.status(404).json({ error: 'Admission not found' })

  row.status = mappedStatus
  row.decisionBy = req.user.name || req.user.email
  row.decisionAt = nowIso()
  row.updatedAt = nowIso()

  if (mappedStatus === 'approved') {
    const activeYear = getActiveAcademicYear()
    const programCode = row.programCode || getProgramCodeById(row.programId) || 'GEN'
    const yearTag = activeYear?.name?.split('/')[0] || String(new Date().getFullYear())
    if (!row.registrationNumber) row.registrationNumber = nextStudentRegNo(programCode, yearTag)
    row.academicYearId = activeYear?.id || row.academicYearId || null

    let studentUser = store.users.find((u) => u.email === row.email)
    if (!studentUser) {
      const generatedPassword = generateTemporaryPassword(12)
      const hash = await bcrypt.hash(generatedPassword, 10)
      studentUser = {
        id: nextId('users'),
        email: row.email,
        name: row.name,
        password: hash,
        role: 'student',
        twoFactorEnabled: false
      }
      store.users.push(studentUser)
      if (STORAGE_ENGINE === 'prisma' && prisma) {
        try {
          const existingDb = await prisma.user.findUnique({ where: { email: row.email } })
          if (!existingDb) {
            const createdDb = await prisma.user.create({
              data: {
                email: row.email,
                name: row.name,
                password: hash,
                role: 'STUDENT',
                twoFactorEnabled: false
              }
            })
            studentUser.id = createdDb.id
          } else {
            studentUser.id = existingDb.id
          }
        } catch (error) {
          console.error('prisma student create error', error)
        }
      }
      const generatedUsername = ensureUniqueUsername(generateUsername(row.name, row.registrationNumber || row.programCode || 'STD'))
      upsertAccountProfile(studentUser.id, {
        username: generatedUsername,
        personNumber: row.registrationNumber || '',
        phone: row.phone || '',
        programId: row.programId || null,
        mustChangePassword: true
      })
      store.notifications.push({
        id: nextId('notifications'),
        channel: 'email',
        audience: 'targeted',
        toUserId: studentUser.id,
        message: `Admission approved. Username: ${generatedUsername}. Temporary password issued and must be changed at first login.`,
        status: 'queued',
        sentBy: req.user.id,
        createdAt: nowIso()
      })
      try {
        await sendTemporaryPasswordEmail(row.email, generatedUsername, generatedPassword)
      } catch (error) {
        console.error('admission credentials email failed', error)
      }
    }

    const profile = ensureStudentProfileForUser(studentUser)
    profile.registrationNumber = row.registrationNumber
    profile.programId = row.programId || profile.programId || 1
    profile.academicYearId = row.academicYearId || profile.academicYearId
    profile.status = 'active'
    profile.isSuspended = false
    upsertAccountProfile(studentUser.id, {
      username: accountProfileForUser(studentUser.id)?.username || ensureUniqueUsername(generateUsername(row.name, row.registrationNumber || 'STD')),
      personNumber: row.registrationNumber || accountProfileForUser(studentUser.id)?.personNumber || '',
      phone: row.phone || accountProfileForUser(studentUser.id)?.phone || '',
      programId: row.programId || accountProfileForUser(studentUser.id)?.programId || null
    })
  }

  if (STORAGE_ENGINE === 'prisma') {
    const dbStatus = mappedStatus.toUpperCase()
    prisma.admission.update({
      where: { id },
      data: { status: dbStatus }
    }).catch((error) => console.error('prisma admission sync error', error))
  }

  saveStore()
  logActivity(req.user.id, 'admin.admission.update', { admissionId: row.id, status: row.status, registrationNumber: row.registrationNumber || null })
  res.json(row)
})

app.delete('/api/admin/admissions/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  if (STORAGE_ENGINE === 'prisma') {
    prisma.admission.findUnique({ where: { id } }).then((row) => {
      if (!row) return res.status(404).json({ error: 'Admission not found' })
      return prisma.admission.delete({ where: { id } }).then((removed) => {
        logActivity(req.user.id, 'admin.admission.delete', { admissionId: removed.id })
        res.json({ ok: true, deletedAdmissionId: removed.id })
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to delete admission' })
    })
    return
  }

  const index = store.admissions.findIndex((item) => item.id === id)
  if (index === -1) return res.status(404).json({ error: 'Admission not found' })
  const [removed] = store.admissions.splice(index, 1)
  saveStore()
  logActivity(req.user.id, 'admin.admission.delete', { admissionId: removed.id })
  res.json({ ok: true, deletedAdmissionId: removed.id })
})

app.get('/api/admin/registration/pending', auth, requireRole(['admin']), (_req, res) => {
  const rows = store.registrationApprovals
    .filter((r) => r.status === 'pending')
    .map((r) => ({
      ...r,
      studentName: store.users.find((u) => u.id === r.studentId)?.name || '-',
      courseCode: store.hierarchyCourses.find((c) => c.id === r.courseId)?.code || '-',
      courseTitle: store.hierarchyCourses.find((c) => c.id === r.courseId)?.title || '-'
    }))
  res.json(rows)
})

app.patch('/api/admin/registration/pending/:id', auth, requireRole(['admin']), (req, res) => {
  const row = store.registrationApprovals.find((r) => r.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Pending registration not found' })
  const decision = String(req.body.decision || '').toLowerCase()
  if (!['approved', 'rejected'].includes(decision)) return res.status(400).json({ error: 'decision must be approved|rejected' })
  row.status = decision
  row.reviewedBy = req.user.id
  row.reviewedAt = nowIso()
  const registration = store.courseRegistrations.find((c) => c.id === row.registrationId)
  if (registration) registration.status = decision === 'approved' ? 'registered' : 'rejected'

  if (decision === 'approved' && registration) {
    const course = store.hierarchyCourses.find((c) => c.id === registration.courseId)
    const amount = Number(course?.creditHours || 0) * 100
    const invoice = {
      id: nextId('invoices'),
      studentId: registration.studentId,
      semesterId: registration.semesterId,
      amount,
      description: `Tuition invoice for approved registration (${course?.code || ''})`,
      status: 'unpaid',
      createdAt: nowIso()
    }
    store.invoices.push(invoice)
    const account = ensureFinanceAccount(registration.studentId)
    account.tuitionBalance = Number(account.tuitionBalance || 0) + amount
    account.updatedAt = nowIso()
  }

  saveStore()
  logActivity(req.user.id, 'admin.registration.review', { approvalId: row.id, decision })
  res.json(row)
})

app.get('/api/admin/registration/overview', auth, requireRole(['admin']), (_req, res) => {
  const registered = store.courseRegistrations.filter((r) => r.status === 'registered')
  const pending = store.courseRegistrations.filter((r) => r.status === 'pending')
  const studentIds = new Set(store.students.map((s) => s.userId))
  const registeredStudentIds = new Set(registered.map((r) => r.studentId))
  const byProgram = store.hierarchyPrograms.map((program) => ({
    programId: program.id,
    programName: program.name,
    registeredStudents: store.students.filter((s) => s.programId === program.id && registeredStudentIds.has(s.userId)).length
  }))
  const financialSummary = {
    totalInvoiceAmount: store.invoices.reduce((sum, i) => sum + Number(i.amount || 0), 0),
    unpaidInvoices: store.invoices.filter((i) => i.status === 'unpaid').length
  }
  res.json({
    totalStudents: studentIds.size,
    studentsRegistered: registeredStudentIds.size,
    studentsNotRegistered: Math.max(0, studentIds.size - registeredStudentIds.size),
    totalRegisteredCourses: registered.length,
    pendingApprovals: pending.length,
    byProgram,
    financialSummary
  })
})

app.get('/api/admin/registration/policy', auth, requireRole(['admin']), (_req, res) => {
  res.json(store.registrationPolicy || {})
})

app.patch('/api/admin/registration/policy', auth, requireRole(['admin']), (req, res) => {
  const current = store.registrationPolicy || {}
  const next = {
    ...current,
    maxCredits: req.body.maxCredits !== undefined ? Number(req.body.maxCredits) : current.maxCredits,
    minCredits: req.body.minCredits !== undefined ? Number(req.body.minCredits) : current.minCredits,
    minGpa: req.body.minGpa !== undefined ? Number(req.body.minGpa) : current.minGpa,
    feeThresholdPercent: req.body.feeThresholdPercent !== undefined ? Number(req.body.feeThresholdPercent) : current.feeThresholdPercent,
    approvalModel: req.body.approvalModel || current.approvalModel || 'advisor'
  }
  store.registrationPolicy = next
  saveStore()
  logActivity(req.user.id, 'admin.registration.policy.update', next)
  res.json(next)
})

app.post('/api/admin/registration/automation/run', auth, requireRole(['admin']), (_req, res) => {
  const flaggedLowGpa = []
  const flaggedMissingCore = []
  store.students.forEach((student) => {
    const gpa = currentGpaForStudent(student.userId)
    student.gpa = gpa
    if (gpa > 0 && gpa < 2.0) {
      student.status = 'flagged'
      flaggedLowGpa.push(student.userId)
    }
    const requiredCore = store.hierarchyCourses
      .filter((c) => c.programId === student.programId && Number(c.year) <= Number(student.yearOfStudy))
      .map((c) => c.code)
    const done = buildStudentResults(student.userId).rows.map((r) => r.courseCode)
    const missing = requiredCore.filter((code) => !done.includes(code))
    if (missing.length) {
      flaggedMissingCore.push({ userId: student.userId, missingCore: missing })
    } else if (student.status === 'active' && gpa >= 2.0) {
      student.yearOfStudy = Math.min(8, Number(student.yearOfStudy || 1) + 1)
    }
  })
  saveStore()
  logActivity(req.user.id, 'admin.registration.automation.run', { flaggedLowGpa: flaggedLowGpa.length, flaggedMissingCore: flaggedMissingCore.length })
  res.json({ ok: true, flaggedLowGpa, flaggedMissingCore })
})

app.get('/api/admin/reports/performance', auth, requireRole(['admin']), (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.course.findMany({ include: { results: true } }).then((courses) => {
      const byCourse = courses.map((course) => {
        const avg = course.results.length
          ? Number((course.results.reduce((s, r) => s + r.score, 0) / course.results.length).toFixed(2))
          : 0
        return { courseId: course.id, code: course.code, title: course.title, averageScore: avg }
      })
      res.json(byCourse)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to build performance report' })
    })
    return
  }
  const byCourse = store.courses.map((course) => {
    const courseResults = store.results.filter((r) => r.courseId === course.id)
    const avg = courseResults.length
      ? Number((courseResults.reduce((s, r) => s + r.score, 0) / courseResults.length).toFixed(2))
      : 0
    return { courseId: course.id, code: course.code, title: course.title, averageScore: avg }
  })
  res.json(byCourse)
})

app.get('/api/admin/reports/finance', auth, requireRole(['admin']), (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    Promise.all([
      prisma.payment.aggregate({ _sum: { amount: true } }),
      prisma.financeAccount.aggregate({ _sum: { tuitionBalance: true, upkeepBalance: true } })
    ]).then(([payments, balances]) => {
      res.json({
        totalPaid: Number(payments._sum.amount || 0),
        totalTuitionOutstanding: Number(balances._sum.tuitionBalance || 0),
        totalUpkeepOutstanding: Number(balances._sum.upkeepBalance || 0)
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to build finance report' })
    })
    return
  }
  const totalPaid = store.payments.reduce((sum, p) => sum + p.amount, 0)
  const totalTuitionOutstanding = store.financeAccounts.reduce((sum, a) => sum + a.tuitionBalance, 0)
  const totalUpkeepOutstanding = store.financeAccounts.reduce((sum, a) => sum + a.upkeepBalance, 0)
  res.json({ totalPaid, totalTuitionOutstanding, totalUpkeepOutstanding })
})

app.get('/api/admin/reports/enrollment', auth, requireRole(['admin']), (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    Promise.all([
      prisma.department.findMany({ include: { courses: true } }),
      prisma.courseRegistration.findMany({ where: { status: 'registered' } })
    ]).then(([departments, registrations]) => {
      const byDepartment = departments.map((department) => {
        const courseIds = department.courses.map((c) => c.id)
        const count = registrations.filter((r) => courseIds.includes(r.courseId)).length
        return { departmentId: department.id, department: department.name, activeRegistrations: count }
      })
      res.json(byDepartment)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to build enrollment report' })
    })
    return
  }
  const byDepartment = store.departments.map((department) => {
    const courseIds = store.courses.filter((c) => c.departmentId === department.id).map((c) => c.id)
    const count = store.courseRegistrations.filter((r) => courseIds.includes(r.courseId) && r.status === 'registered').length
    return { departmentId: department.id, department: department.name, activeRegistrations: count }
  })
  res.json(byDepartment)
})

app.get('/api/admin/dashboard-summary', auth, requireRole(['admin']), (_req, res) => {
  const users = store.users || []
  const students = users.filter((u) => normalizeRoleName(getAssignedAccessRole(u.id) || u.role) === 'student')
  const lecturers = users.filter((u) => normalizeRoleName(getAssignedAccessRole(u.id) || u.role) === 'lecturer')
  const staff = users.filter((u) => ['non_teaching_staff', 'finance_officer', 'registrar', 'hod', 'admin', 'super_admin'].includes(normalizeRoleName(getAssignedAccessRole(u.id) || u.role)))

  const maleCount = students.filter((u) => /^mr\.?\s/i.test(String(u.name || ''))).length
  const femaleCount = students.filter((u) => /^ms\.?\s|^mrs\.?\s|^miss\s/i.test(String(u.name || ''))).length
  const unknownCount = Math.max(0, students.length - maleCount - femaleCount)

  const studentProfiles = store.students || []
  const studentsPerDepartment = (store.hierarchyDepartments || []).map((dep) => {
    const programIds = (store.hierarchyPrograms || []).filter((p) => p.departmentId === dep.id).map((p) => p.id)
    const count = studentProfiles.filter((s) => programIds.includes(Number(s.programId))).length
    return { label: dep.name, value: count }
  }).filter((row) => row.value > 0)

  const paidTotal = (store.payments || []).reduce((sum, p) => sum + Number(p.amount || 0), 0)
  const pendingTotal = (store.financeAccounts || []).reduce((sum, a) => sum + Number(a.tuitionBalance || 0) + Number(a.upkeepBalance || 0), 0)

  const admissionRows = store.admissions || []
  const monthBuckets = {}
  admissionRows.forEach((row) => {
    const d = new Date(row.createdAt || nowIso())
    const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`
    monthBuckets[key] = (monthBuckets[key] || 0) + 1
  })
  const enrollmentTrend = Object.keys(monthBuckets).sort().slice(-6).map((k) => ({ month: k, value: monthBuckets[k] }))

  const attendanceByStudent = {}
  ;(store.attendance || []).forEach((a) => {
    attendanceByStudent[a.studentId] = attendanceByStudent[a.studentId] || { total: 0, present: 0 }
    attendanceByStudent[a.studentId].total += 1
    if (a.present) attendanceByStudent[a.studentId].present += 1
  })
  const attendanceSummary = Object.values(attendanceByStudent).reduce((acc, row) => {
    const pct = row.total ? (row.present / row.total) * 100 : 0
    if (pct >= 75) acc.above75 += 1
    else acc.below75 += 1
    return acc
  }, { above75: 0, below75: 0 })

  const gradeDistributionMap = { A: 0, B: 0, C: 0, D: 0, F: 0 }
  ;(store.results || []).forEach((r) => {
    if (gradeDistributionMap[r.grade] !== undefined) gradeDistributionMap[r.grade] += 1
  })

  res.json({
    cards: {
      totalStudents: students.length,
      totalLecturers: lecturers.length,
      totalStaff: staff.length,
      totalCourses: (store.hierarchyCourses || store.courses || []).length,
      totalRevenue: Number(paidTotal.toFixed(2)),
      pendingBalances: Number(pendingTotal.toFixed(2))
    },
    charts: {
      studentGender: [
        { label: 'Male', value: maleCount },
        { label: 'Female', value: femaleCount },
        { label: 'Unspecified', value: unknownCount }
      ],
      staffComposition: [
        { label: 'Lecturers', value: lecturers.length },
        { label: 'Non-Teaching/Admin', value: staff.length }
      ],
      feesStatus: [
        { label: 'Paid', value: Number(paidTotal.toFixed(2)) },
        { label: 'Pending', value: Number(pendingTotal.toFixed(2)) }
      ],
      studentsPerDepartment: studentsPerDepartment.length ? studentsPerDepartment : [{ label: 'No Data', value: 0 }],
      enrollmentTrend: enrollmentTrend.length ? enrollmentTrend : [{ month: 'N/A', value: 0 }],
      attendance: [
        { label: '>= 75%', value: attendanceSummary.above75 },
        { label: '< 75%', value: attendanceSummary.below75 }
      ],
      gradeDistribution: Object.entries(gradeDistributionMap).map(([label, value]) => ({ label, value }))
    }
  })
})

app.get('/api/admin/overview', auth, requireRole(['admin']), (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    Promise.all([
      prisma.user.count({ where: { role: 'STUDENT' } }),
      prisma.user.count({ where: { role: 'LECTURER' } }),
      prisma.user.count({ where: { role: 'ADMIN' } }),
      prisma.course.count(),
      prisma.courseRegistration.count({ where: { status: 'registered' } }),
      prisma.clearanceRequest.count({ where: { status: 'PENDING' } }),
      prisma.financeAccount.aggregate({ _sum: { tuitionBalance: true, upkeepBalance: true } })
    ]).then(([students, lecturers, admins, activeCourses, activeRegistrations, unresolvedClearances, balances]) => {
      const totalOutstanding = Number(balances._sum.tuitionBalance || 0) + Number(balances._sum.upkeepBalance || 0)
      res.json({
        users: { students, lecturers, admins },
        activeCourses,
        activeRegistrations,
        unresolvedClearances,
        totalOutstanding
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load admin overview' })
    })
    return
  }
  const students = store.users.filter((u) => u.role === 'student').length
  const lecturers = store.users.filter((u) => u.role === 'lecturer').length
  const admins = store.users.filter((u) => u.role === 'admin').length
  const activeCourses = store.courses.length
  const activeRegistrations = store.courseRegistrations.filter((r) => r.status === 'registered').length
  const unresolvedClearances = store.clearanceRequests.filter((r) => r.status === 'pending').length
  const totalOutstanding = store.financeAccounts.reduce((sum, a) => sum + a.tuitionBalance + a.upkeepBalance, 0)
  res.json({
    users: { students, lecturers, admins },
    activeCourses,
    activeRegistrations,
    unresolvedClearances,
    totalOutstanding
  })
})

app.get('/api/academics/calendar', auth, (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.calendarEvent.findMany({ orderBy: { date: 'asc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load calendar' })
      })
    return
  }
  res.json(store.academicCalendar)
})

app.post('/api/academics/calendar', auth, requireRole(['admin']), (req, res) => {
  const { title, date, type = 'academic' } = req.body
  if (!title || !date) return res.status(400).json({ error: 'title and date are required' })
  if (STORAGE_ENGINE === 'prisma') {
    prisma.calendarEvent.create({
      data: { title, date: new Date(date), type }
    }).then((row) => {
      logActivity(req.user.id, 'academic.calendar.create', { eventId: row.id })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create calendar event' })
    })
    return
  }
  const row = { id: nextId('academicCalendar'), title, date, type }
  store.academicCalendar.push(row)
  saveStore()
  logActivity(req.user.id, 'academic.calendar.create', { eventId: row.id })
  res.status(201).json(row)
})

app.get('/api/lms/integrations', auth, (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.lmsIntegration.findMany({ orderBy: { id: 'asc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load LMS integrations' })
      })
    return
  }
  res.json(store.lmsIntegrations)
})

app.post('/api/lms/integrations', auth, requireRole(['admin']), (req, res) => {
  const { provider, enabled = true, url = '' } = req.body
  if (!provider) return res.status(400).json({ error: 'provider is required' })
  if (STORAGE_ENGINE === 'prisma') {
    prisma.lmsIntegration.create({
      data: { provider, enabled: Boolean(enabled), url, linkedAt: new Date() }
    }).then((row) => {
      logActivity(req.user.id, 'lms.integration.add', { integrationId: row.id, provider })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create LMS integration' })
    })
    return
  }
  const row = {
    id: nextId('lmsIntegrations'),
    provider,
    enabled: Boolean(enabled),
    url,
    linkedAt: nowIso()
  }
  store.lmsIntegrations.push(row)
  saveStore()
  logActivity(req.user.id, 'lms.integration.add', { integrationId: row.id, provider })
  res.status(201).json(row)
})

app.get('/api/lms/overview', auth, (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    Promise.all([
      prisma.lmsIntegration.findMany({ where: { enabled: true } }),
      prisma.assignment.count(),
      prisma.submission.count()
    ]).then(([enabledProviders, assignmentCount, submissionCount]) => {
      res.json({
        enabledProviders,
        assignmentCount,
        submissionCount,
        discussionForums: [
          { id: 1, topic: 'Algorithms Q&A', posts: 12 },
          { id: 2, topic: 'Project Ideas', posts: 7 }
        ],
        quizzes: [
          { id: 1, title: 'Data Structures Quiz', totalMarks: 30 },
          { id: 2, title: 'Networks Quiz', totalMarks: 20 }
        ]
      })
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load LMS overview' })
    })
    return
  }
  const enabledProviders = store.lmsIntegrations.filter((i) => i.enabled)
  const assignmentCount = store.assignments.length
  const submissionCount = store.submissions.length
  res.json({
    enabledProviders,
    assignmentCount,
    submissionCount,
    discussionForums: [
      { id: 1, topic: 'Algorithms Q&A', posts: 12 },
      { id: 2, topic: 'Project Ideas', posts: 7 }
    ],
    quizzes: [
      { id: 1, title: 'Data Structures Quiz', totalMarks: 30 },
      { id: 2, title: 'Networks Quiz', totalMarks: 20 }
    ]
  })
})

app.get('/api/exams/overview', auth, requireRole(['admin']), (_req, res) => {
  const data = {
    sessions: (store.examSessions || []).length,
    schedules: (store.examSchedules || []).length,
    papers: (store.examPapers || []).length,
    marks: (store.examMarks || []).length,
    moderationPending: (store.examModerations || []).filter((m) => m.status === 'pending').length,
    approvalsPending: (store.resultApprovals || []).filter((a) => a.status === 'pending').length,
    releasedResults: (store.resultApprovals || []).filter((a) => a.status === 'released').length
  }
  res.json(data)
})

app.get('/api/exams/sessions', auth, requireRole(['admin']), (_req, res) => {
  res.json(store.examSessions || [])
})

app.post('/api/exams/sessions', auth, requireRole(['admin']), (req, res) => {
  const { academicYear, semester, examType, startDate, endDate, status = 'draft' } = req.body || {}
  if (!academicYear || !semester || !examType || !startDate || !endDate) {
    return res.status(400).json({ error: 'academicYear, semester, examType, startDate, endDate are required' })
  }
  const row = {
    id: nextId('examSessions'),
    academicYear,
    semester,
    examType,
    startDate,
    endDate,
    status
  }
  store.examSessions.push(row)
  saveStore()
  res.status(201).json(row)
})

app.patch('/api/exams/sessions/:id', auth, requireRole(['admin']), (req, res) => {
  const row = (store.examSessions || []).find((s) => s.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Exam session not found' })
  Object.assign(row, req.body || {})
  saveStore()
  res.json(row)
})

app.delete('/api/exams/sessions/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  const idx = (store.examSessions || []).findIndex((s) => s.id === id)
  if (idx === -1) return res.status(404).json({ error: 'Exam session not found' })
  store.examSessions.splice(idx, 1)
  saveStore()
  res.json({ ok: true })
})

app.get('/api/exams/schedules', auth, (req, res) => {
  const role = normalizeRoleName(req.user.role)
  let rows = store.examSchedules || []
  if (role === 'student') {
    const registered = store.courseRegistrations.filter((r) => r.studentId === req.user.id && r.status !== 'dropped')
    const allowed = new Set(registered.map((r) => r.courseId))
    rows = rows.filter((r) => r.published && allowed.has(r.courseId))
  } else if (role === 'lecturer') {
    const taught = store.courses.filter((c) => c.lecturerId === req.user.id).map((c) => c.id)
    const allowed = new Set(taught)
    rows = rows.filter((r) => allowed.has(r.courseId))
  }
  res.json(rows)
})

app.post('/api/exams/schedules', auth, requireRole(['admin']), (req, res) => {
  const { sessionId, courseId, examDate, examTime, examRoom, invigilator, published = false } = req.body || {}
  const course = store.courses.find((c) => c.id === Number(courseId))
  if (!sessionId || !course || !examDate || !examTime || !examRoom) {
    return res.status(400).json({ error: 'sessionId, courseId, examDate, examTime, examRoom are required' })
  }
  const row = {
    id: nextId('examSchedules'),
    sessionId: Number(sessionId),
    courseId: Number(courseId),
    courseCode: course.code,
    courseTitle: course.title,
    examDate,
    examTime,
    examRoom,
    invigilator: invigilator || '',
    published: Boolean(published)
  }
  store.examSchedules.push(row)
  saveStore()
  res.status(201).json(row)
})

app.patch('/api/exams/schedules/:id', auth, requireRole(['admin']), (req, res) => {
  const row = (store.examSchedules || []).find((s) => s.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Schedule not found' })
  Object.assign(row, req.body || {})
  saveStore()
  res.json(row)
})

app.post('/api/exams/schedules/:id/publish', auth, requireRole(['admin']), (req, res) => {
  const row = (store.examSchedules || []).find((s) => s.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Schedule not found' })
  row.published = true
  saveStore()
  res.json(row)
})

app.delete('/api/exams/schedules/:id', auth, requireRole(['admin']), (req, res) => {
  const id = Number(req.params.id)
  const idx = (store.examSchedules || []).findIndex((s) => s.id === id)
  if (idx === -1) return res.status(404).json({ error: 'Schedule not found' })
  store.examSchedules.splice(idx, 1)
  saveStore()
  res.json({ ok: true })
})

app.get('/api/exams/papers', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const role = normalizeRoleName(req.user.role)
  let rows = store.examPapers || []
  if (role === 'lecturer') rows = rows.filter((p) => p.createdBy === req.user.id)
  res.json(rows)
})

app.post('/api/exams/papers', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const { courseId, title, type, durationMinutes, totalMarks, fileUrl } = req.body || {}
  const course = store.courses.find((c) => c.id === Number(courseId))
  if (!course || !title || !type) return res.status(400).json({ error: 'courseId, title, type are required' })
  const row = {
    id: nextId('examPapers'),
    courseId: Number(courseId),
    courseCode: course.code,
    title,
    type,
    durationMinutes: Number(durationMinutes || 0),
    totalMarks: Number(totalMarks || 0),
    fileUrl: fileUrl || '',
    createdBy: req.user.id
  }
  store.examPapers.push(row)
  saveStore()
  res.status(201).json(row)
})

app.patch('/api/exams/papers/:id', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const row = (store.examPapers || []).find((p) => p.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Exam paper not found' })
  if (normalizeRoleName(req.user.role) === 'lecturer' && row.createdBy !== req.user.id) {
    return res.status(403).json({ error: 'Not allowed to edit this paper' })
  }
  Object.assign(row, req.body || {})
  saveStore()
  res.json(row)
})

app.delete('/api/exams/papers/:id', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const id = Number(req.params.id)
  const idx = (store.examPapers || []).findIndex((p) => p.id === id)
  if (idx === -1) return res.status(404).json({ error: 'Exam paper not found' })
  const row = store.examPapers[idx]
  if (normalizeRoleName(req.user.role) === 'lecturer' && row.createdBy !== req.user.id) {
    return res.status(403).json({ error: 'Not allowed to delete this paper' })
  }
  store.examPapers.splice(idx, 1)
  saveStore()
  res.json({ ok: true })
})

app.get('/api/exams/marks', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const role = normalizeRoleName(req.user.role)
  let rows = store.examMarks || []
  if (role === 'lecturer') {
    const courses = store.courses.filter((c) => c.lecturerId === req.user.id).map((c) => c.id)
    const allowed = new Set(courses)
    rows = rows.filter((m) => allowed.has(m.courseId))
  }
  res.json(rows)
})

app.post('/api/exams/marks', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const { studentId, courseId, catMarks = 0, assignmentMarks = 0, examMarks = 0, status = 'draft', sessionId = null } = req.body || {}
  const student = store.users.find((u) => u.id === Number(studentId))
  const course = store.courses.find((c) => c.id === Number(courseId))
  if (!student || !course) return res.status(400).json({ error: 'studentId and courseId are required' })
  const calc = computeExamTotals(catMarks, assignmentMarks, examMarks)
  const row = {
    id: nextId('examMarks'),
    studentId: Number(studentId),
    courseId: Number(courseId),
    catMarks: Number(catMarks || 0),
    assignmentMarks: Number(assignmentMarks || 0),
    examMarks: Number(examMarks || 0),
    totalMarks: calc.totalMarks,
    grade: calc.grade,
    status,
    sessionId: sessionId ? Number(sessionId) : null,
    submittedBy: req.user.id,
    createdAt: nowIso()
  }
  store.examMarks.push(row)
  saveStore()
  if (status === 'submitted') {
    const existing = store.examModerations.find((m) => m.courseId === Number(courseId))
    if (!existing) {
      store.examModerations.push({
        id: nextId('examModerations'),
        courseId: Number(courseId),
        courseCode: course.code,
        lecturerId: course.lecturerId,
        status: 'pending',
        notes: 'Submitted marks awaiting moderation',
        reviewedBy: null,
        reviewedAt: null
      })
      saveStore()
    }
  }
  res.status(201).json(row)
})

app.patch('/api/exams/marks/:id', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const row = (store.examMarks || []).find((m) => m.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Marks not found' })
  const next = { ...row, ...(req.body || {}) }
  const calc = computeExamTotals(next.catMarks, next.assignmentMarks, next.examMarks)
  row.catMarks = Number(next.catMarks || 0)
  row.assignmentMarks = Number(next.assignmentMarks || 0)
  row.examMarks = Number(next.examMarks || 0)
  row.totalMarks = calc.totalMarks
  row.grade = calc.grade
  if (next.status) row.status = next.status
  saveStore()
  res.json(row)
})

app.delete('/api/exams/marks/:id', auth, requireRole(['lecturer', 'admin']), (req, res) => {
  const id = Number(req.params.id)
  const idx = (store.examMarks || []).findIndex((m) => m.id === id)
  if (idx === -1) return res.status(404).json({ error: 'Marks not found' })
  const row = store.examMarks[idx]
  if (normalizeRoleName(req.user.role) === 'lecturer') {
    const course = store.courses.find((c) => c.id === row.courseId)
    if (!course || course.lecturerId !== req.user.id) {
      return res.status(403).json({ error: 'Not allowed to delete these marks' })
    }
  }
  store.examMarks.splice(idx, 1)
  saveStore()
  res.json({ ok: true })
})

app.get('/api/exams/moderation', auth, requireRole(['admin']), (_req, res) => {
  res.json(store.examModerations || [])
})

app.patch('/api/exams/moderation/:id/approve', auth, requireRole(['admin']), (req, res) => {
  const row = (store.examModerations || []).find((m) => m.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Moderation record not found' })
  row.status = 'approved'
  row.reviewedBy = req.user.id
  row.reviewedAt = nowIso()
  saveStore()
  const approval = store.resultApprovals.find((a) => a.courseId === row.courseId)
  if (!approval) {
    store.resultApprovals.push({
      id: nextId('resultApprovals'),
      courseId: row.courseId,
      courseCode: row.courseCode,
      sessionId: null,
      status: 'pending',
      approvedBy: null,
      approvedAt: null,
      releasedAt: null
    })
    saveStore()
  }
  res.json(row)
})

app.patch('/api/exams/moderation/:id/return', auth, requireRole(['admin']), (req, res) => {
  const row = (store.examModerations || []).find((m) => m.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Moderation record not found' })
  row.status = 'returned'
  row.reviewedBy = req.user.id
  row.reviewedAt = nowIso()
  row.notes = req.body?.notes || row.notes
  saveStore()
  res.json(row)
})

app.get('/api/exams/approvals', auth, requireRole(['admin']), (_req, res) => {
  res.json(store.resultApprovals || [])
})

app.patch('/api/exams/approvals/:id/approve', auth, requireRole(['admin']), (req, res) => {
  const row = (store.resultApprovals || []).find((a) => a.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Approval not found' })
  row.status = 'approved'
  row.approvedBy = req.user.id
  row.approvedAt = nowIso()
  saveStore()
  res.json(row)
})

app.patch('/api/exams/approvals/:id/reject', auth, requireRole(['admin']), (req, res) => {
  const row = (store.resultApprovals || []).find((a) => a.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Approval not found' })
  row.status = 'rejected'
  row.rejectedAt = nowIso()
  row.rejectedReason = req.body?.reason || 'Rejected'
  saveStore()
  res.json(row)
})

app.patch('/api/exams/approvals/:id/release', auth, requireRole(['admin']), (req, res) => {
  const row = (store.resultApprovals || []).find((a) => a.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Approval not found' })
  row.status = 'released'
  row.releasedAt = nowIso()
  saveStore()
  const marks = (store.examMarks || []).filter((m) => m.courseId === row.courseId)
  marks.forEach((mark) => {
    const existing = store.results.find((r) => r.studentId === mark.studentId && r.courseId === mark.courseId)
    if (existing) {
      existing.score = mark.totalMarks
      existing.grade = mark.grade
      existing.approved = true
    } else {
      store.results.push({
        id: nextId('results'),
        studentId: mark.studentId,
        courseId: mark.courseId,
        score: mark.totalMarks,
        grade: mark.grade,
        semesterCode: store.semesters[0]?.code || '2026-S1',
        approved: true
      })
    }
  })
  saveStore()
  res.json(row)
})

app.get('/api/exams/results', auth, requireRole(['student']), (req, res) => {
  res.json(buildStudentResults(req.user.id))
})

app.get('/api/exams/transcripts', auth, (req, res) => {
  const role = normalizeRoleName(req.user.role)
  if (role === 'student') {
    return res.json({
      ...buildStudentResults(req.user.id),
      studentId: req.user.id
    })
  }
  const rows = store.users.filter((u) => normalizeRoleName(u.role) === 'student').map((u) => {
    const results = buildStudentResults(u.id)
    return {
      studentId: u.id,
      name: u.name,
      email: u.email,
      cgpa: results.cgpa,
      totalCredits: results.totalCredits
    }
  })
  res.json(rows)
})

app.get('/api/extras/hostels', auth, (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    const where = req.user.role === 'student' ? { studentId: req.user.id } : {}
    prisma.hostelAllocation.findMany({ where, orderBy: { allocatedAt: 'desc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load hostels' })
      })
    return
  }
  if (req.user.role === 'student') {
    const mine = store.hostelAllocations.filter((h) => h.studentId === req.user.id)
    return res.json(mine)
  }
  return res.json(store.hostelAllocations)
})

app.post('/api/extras/hostels', auth, requireRole(['admin']), (req, res) => {
  const { studentId, hostel, room } = req.body
  if (STORAGE_ENGINE === 'prisma') {
    prisma.hostelAllocation.create({
      data: { studentId: Number(studentId), hostel, room, allocatedAt: new Date() }
    }).then((row) => {
      logActivity(req.user.id, 'extra.hostel.allocate', { allocationId: row.id })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to allocate hostel' })
    })
    return
  }
  const row = {
    id: nextId('hostelAllocations'),
    studentId: Number(studentId),
    hostel,
    room,
    allocatedAt: nowIso()
  }
  store.hostelAllocations.push(row)
  saveStore()
  logActivity(req.user.id, 'extra.hostel.allocate', { allocationId: row.id })
  res.status(201).json(row)
})

app.get('/api/extras/library', auth, (_req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.libraryItem.findMany({ orderBy: { id: 'asc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load library items' })
      })
    return
  }
  res.json(store.libraryItems)
})

app.post('/api/documents', auth, (req, res) => {
  const { name, type = 'general', mime = 'application/octet-stream', data } = req.body || {}
  if (!name || !data) return res.status(400).json({ error: 'name and data are required' })
  const payload = { name, type, mime, data, userId: req.user.id, createdAt: nowIso() }
  if (STORAGE_ENGINE === 'prisma') {
    prisma.document.create({ data: { ...payload, userId: req.user.id } })
      .then((row) => res.status(201).json(row))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to save document' })
      })
    return
  }
  const row = { id: nextId('documents'), ...payload }
  store.documents.push(row)
  saveStore()
  res.status(201).json(row)
})

app.get('/api/documents', auth, (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    const where = req.user.role === 'admin' ? {} : { userId: req.user.id }
    prisma.document.findMany({ where, orderBy: { createdAt: 'desc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load documents' })
      })
    return
  }
  const rows = req.user.role === 'admin'
    ? store.documents
    : store.documents.filter((d) => d.userId === req.user.id)
  res.json(rows)
})

app.get('/api/documents/:id', auth, (req, res) => {
  const id = Number(req.params.id)
  const doc = (STORAGE_ENGINE === 'prisma')
    ? null
    : store.documents.find((d) => d.id === id)
  if (STORAGE_ENGINE === 'prisma') {
    prisma.document.findUnique({ where: { id } }).then((row) => {
      if (!row) return res.status(404).json({ error: 'Document not found' })
      if (req.user.role !== 'admin' && row.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' })
      res.json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to load document' })
    })
    return
  }
  if (!doc) return res.status(404).json({ error: 'Document not found' })
  if (req.user.role !== 'admin' && doc.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' })
  res.json(doc)
})

app.post('/api/auth/forgot-password', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase()
  if (!email) return res.status(400).json({ error: 'Email is required' })
  const user = STORAGE_ENGINE === 'prisma'
    ? null
    : store.users.find((u) => String(u.email || '').toLowerCase() === email)
  const findUser = async () => {
    if (STORAGE_ENGINE === 'prisma') {
      return prisma.user.findUnique({ where: { email } })
    }
    return user
  }
  findUser().then((u) => {
    if (!u) return res.status(404).json({ error: 'User not found' })
    const token = `${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000)
    if (STORAGE_ENGINE === 'prisma') {
      prisma.passwordReset.create({ data: { userId: u.id, token, expiresAt, used: false } })
        .then(() => {
          sendPasswordResetEmail(u.email, token, expiresAt)
            .then(() => {
              logActivity(u.id, 'auth.password.reset.request', {})
              res.json({ ok: true })
            })
            .catch((error) => {
              console.error('password reset email failed', error)
              res.status(500).json({ error: 'Failed to send reset email. Check email configuration and try again.' })
            })
        }).catch((error) => {
          console.error(error)
          res.status(500).json({ error: 'Failed to create reset token' })
        })
      return
    }
    store.passwordResets.push({ id: nextId('passwordResets'), userId: u.id, token, expiresAt: expiresAt.toISOString(), used: false })
    saveStore()
    sendPasswordResetEmail(u.email, token, expiresAt)
      .then(() => {
        logActivity(u.id, 'auth.password.reset.request', {})
        res.json({ ok: true })
      })
      .catch((error) => {
        console.error('password reset email failed', error)
        res.status(500).json({ error: 'Failed to send reset email. Check email configuration and try again.' })
      })
  }).catch((error) => {
    console.error(error)
    res.status(500).json({ error: 'Failed to process request' })
  })
})

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body || {}
  if (!token || !newPassword) return res.status(400).json({ error: 'token and newPassword are required' })
  if (String(newPassword).length < 8) return res.status(400).json({ error: 'newPassword must be at least 8 characters' })
  const now = new Date()
  if (STORAGE_ENGINE === 'prisma') {
    const reset = await prisma.passwordReset.findUnique({ where: { token } })
    if (!reset || reset.used || reset.expiresAt < now) return res.status(400).json({ error: 'Invalid or expired token' })
    const hash = await bcrypt.hash(newPassword, 10)
    await prisma.user.update({ where: { id: reset.userId }, data: { password: hash } })
    await prisma.passwordReset.update({ where: { token }, data: { used: true } })
    logActivity(reset.userId, 'auth.password.reset', {})
    return res.json({ ok: true })
  }
  const reset = store.passwordResets.find((r) => r.token === token)
  if (!reset || reset.used || new Date(reset.expiresAt) < now) return res.status(400).json({ error: 'Invalid or expired token' })
  const user = store.users.find((u) => u.id === reset.userId)
  if (!user) return res.status(404).json({ error: 'User not found' })
  user.password = await bcrypt.hash(newPassword, 10)
  reset.used = true
  saveStore()
  logActivity(user.id, 'auth.password.reset', {})
  res.json({ ok: true })
})

app.get('/api/extras/clearance', auth, (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    const where = req.user.role === 'student' ? { studentId: req.user.id } : {}
    prisma.clearanceRequest.findMany({ where, orderBy: { createdAt: 'desc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load clearance requests' })
      })
    return
  }
  const rows = req.user.role === 'student'
    ? store.clearanceRequests.filter((c) => c.studentId === req.user.id)
    : store.clearanceRequests
  res.json(rows)
})

app.post('/api/extras/clearance', auth, requireRole(['student']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.clearanceRequest.create({
      data: {
        studentId: req.user.id,
        reason: req.body.reason || 'General clearance request',
        status: 'PENDING'
      }
    }).then((row) => {
      logActivity(req.user.id, 'extra.clearance.request', { clearanceId: row.id })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create clearance request' })
    })
    return
  }
  const row = {
    id: nextId('clearanceRequests'),
    studentId: req.user.id,
    reason: req.body.reason || 'General clearance request',
    status: 'pending',
    createdAt: nowIso()
  }
  store.clearanceRequests.push(row)
  saveStore()
  logActivity(req.user.id, 'extra.clearance.request', { clearanceId: row.id })
  res.status(201).json(row)
})

app.patch('/api/extras/clearance/:id/review', auth, requireRole(['admin']), (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    prisma.clearanceRequest.update({
      where: { id: Number(req.params.id) },
      data: {
        status: String(req.body.status || 'PENDING').toUpperCase(),
        reviewedById: req.user.id,
        reviewedAt: new Date()
      }
    }).then((row) => {
      logActivity(req.user.id, 'extra.clearance.review', { clearanceId: row.id, status: row.status })
      res.json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to review clearance request' })
    })
    return
  }
  const row = store.clearanceRequests.find((c) => c.id === Number(req.params.id))
  if (!row) return res.status(404).json({ error: 'Clearance request not found' })
  row.status = req.body.status || row.status
  row.reviewedBy = req.user.id
  row.reviewedAt = nowIso()
  saveStore()
  logActivity(req.user.id, 'extra.clearance.review', { clearanceId: row.id, status: row.status })
  res.json(row)
})

app.get('/api/extras/alumni', auth, (req, res) => {
  if (STORAGE_ENGINE === 'prisma') {
    const where = req.user.role === 'student' ? { OR: [{ userId: req.user.id }, { email: req.user.email }] } : {}
    prisma.alumniProfile.findMany({ where, orderBy: { id: 'asc' } })
      .then((rows) => res.json(rows))
      .catch((error) => {
        console.error(error)
        res.status(500).json({ error: 'Failed to load alumni profiles' })
      })
    return
  }
  if (req.user.role === 'student') {
    return res.json(store.alumniProfiles.filter((a) => a.userId === req.user.id || a.email === req.user.email))
  }
  return res.json(store.alumniProfiles)
})

app.post('/api/extras/alumni', auth, requireRole(['admin']), (req, res) => {
  const { name, email, graduationYear, employmentStatus = 'unknown' } = req.body
  if (!name || !email || !graduationYear) return res.status(400).json({ error: 'name, email and graduationYear are required' })
  if (STORAGE_ENGINE === 'prisma') {
    prisma.alumniProfile.create({
      data: {
        userId: req.body.userId ? Number(req.body.userId) : null,
        name,
        email,
        graduationYear: Number(graduationYear),
        employmentStatus
      }
    }).then((row) => {
      logActivity(req.user.id, 'extra.alumni.create', { alumniId: row.id })
      res.status(201).json(row)
    }).catch((error) => {
      console.error(error)
      res.status(500).json({ error: 'Failed to create alumni profile' })
    })
    return
  }
  const row = {
    id: nextId('alumniProfiles'),
    userId: req.body.userId ? Number(req.body.userId) : null,
    name,
    email,
    graduationYear: Number(graduationYear),
    employmentStatus
  }
  store.alumniProfiles.push(row)
  saveStore()
  logActivity(req.user.id, 'extra.alumni.create', { alumniId: row.id })
  res.status(201).json(row)
})

app.post('/api/chatbot/support', auth, (req, res) => {
  const question = String(req.body.question || '').toLowerCase()
  let answer = 'Please contact support@techhub.edu for personalized assistance.'
  if (question.includes('fee')) answer = 'Open Finance > Fee Balance to view tuition and upkeep balances, then use Payments.'
  else if (question.includes('course')) answer = 'Go to Student Dashboard and use course registration to add/drop units.'
  else if (question.includes('result')) answer = 'Open Results + Transcript to view grades, credits and CGPA.'
  else if (question.includes('clearance')) answer = 'Use Extras > Clearance Request. Admin will review and update status.'
  res.json({ question: req.body.question || '', answer, generatedAt: nowIso() })
})

app.get('/api/security/activity-logs', auth, requireRole(['admin']), (_req, res) => {
  res.json([...store.activityLogs].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)))
})

if (fs.existsSync(FRONTEND_DIR)) {
  app.use(express.static(FRONTEND_DIR))
  app.get('/', (_req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'index.html'))
  })
}

app.use(/^\/api\//, (_req, res) => {
  res.status(404).json({ error: 'API endpoint not found' })
})

app.use((err, req, res, _next) => {
  console.error(`[${req.requestId || 'n/a'}]`, err)
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS blocked for this origin' })
  }
  return res.status(500).json({ error: 'Internal server error' })
})

const server = app.listen(PORT, () => {
  if (IS_PROD && SECRET === 'dev-secret') {
    console.warn('JWT_SECRET is using a default value. Set a secure secret in production.')
  }
  if (STORAGE_ENGINE === 'prisma') {
    console.warn('STORAGE_ENGINE=prisma selected. Ensure API handlers are migrated before production cutover.')
  }
  console.log(`Storage engine: ${STORAGE_ENGINE}`)
  console.log(`University Portal API running on http://localhost:${PORT}`)
})

function shutdown(signal) {
  console.log(`${signal} received. Shutting down API server...`)
  server.close(() => {
    const done = () => {
      console.log('Server closed cleanly.')
      process.exit(0)
    }
    if (STORAGE_ENGINE === 'prisma' && prisma) {
      prisma.$disconnect().then(done).catch(done)
      return
    }
    done()
  })
  setTimeout(() => {
    console.error('Force shutdown after timeout.')
    process.exit(1)
  }, 10000).unref()
}

process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))
