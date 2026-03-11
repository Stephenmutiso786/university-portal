const { PrismaClient, Role, PaymentMethod, BalanceTarget } = require('@prisma/client')
const bcrypt = require('bcryptjs')

const prisma = new PrismaClient()

async function upsertUser({ email, name, password, role }) {
  const hashed = await bcrypt.hash(password, 10)
  return prisma.user.upsert({
    where: { email },
    update: { name, role, password: hashed },
    create: {
      email,
      name,
      password: hashed,
      role
    }
  })
}

async function main() {
  const admin = await upsertUser({ email: 'stephemutiso19@gmail.com', name: 'Super Admin', password: '2006@shawn_M', role: Role.ADMIN })
  const lecturer = await upsertUser({ email: 'lecturer@example.com', name: 'Dr. Ada', password: 'lecturerpass', role: Role.LECTURER })
  const student = await upsertUser({ email: 'student@example.com', name: 'Student One', password: 'studentpass', role: Role.STUDENT })
  await upsertUser({ email: 'staff@example.com', name: 'Operations Staff', password: 'staffpass', role: Role.STAFF })

  await prisma.registrationRecord.upsert({
    where: { regNumber: 'CS2024-001' },
    update: { role: 'student', name: 'John Doe', program: 'Computer Science', email: 'johndoe@email.com', dob: new Date('2004-03-10') },
    create: { regNumber: 'CS2024-001', role: 'student', name: 'John Doe', program: 'Computer Science', email: 'johndoe@email.com', dob: new Date('2004-03-10') }
  })
  await prisma.registrationRecord.upsert({
    where: { regNumber: 'STF2024-001' },
    update: { role: 'staff', name: 'Mary Admin', department: 'Operations', position: 'Registrar', email: 'mary.admin@techhub.edu' },
    create: { regNumber: 'STF2024-001', role: 'staff', name: 'Mary Admin', department: 'Operations', position: 'Registrar', email: 'mary.admin@techhub.edu' }
  })
  await prisma.registrationRecord.upsert({
    where: { regNumber: 'LCT2024-001' },
    update: { role: 'lecturer', name: 'Dr. Ada Lovelace', department: 'Computer Science', email: 'ada.lovelace@techhub.edu' },
    create: { regNumber: 'LCT2024-001', role: 'lecturer', name: 'Dr. Ada Lovelace', department: 'Computer Science', email: 'ada.lovelace@techhub.edu' }
  })

  const department = await prisma.department.upsert({
    where: { code: 'CS' },
    update: { name: 'Computer Science' },
    create: { code: 'CS', name: 'Computer Science' }
  })

  const program = await prisma.program.upsert({
    where: { code: 'BSC-CS' },
    update: { name: 'BSc Computer Science', departmentId: department.id },
    create: { code: 'BSC-CS', name: 'BSc Computer Science', departmentId: department.id }
  })

  const semester = await prisma.semester.upsert({
    where: { code: '2026-S1' },
    update: { name: 'Semester 1 2026', startDate: new Date('2026-01-12'), endDate: new Date('2026-05-08') },
    create: { code: '2026-S1', name: 'Semester 1 2026', startDate: new Date('2026-01-12'), endDate: new Date('2026-05-08') }
  })

  const course = await prisma.course.upsert({
    where: { code: 'CS101' },
    update: {
      title: 'Intro to Computer Science',
      credits: 3,
      lecturerId: lecturer.id,
      semesterId: semester.id,
      departmentId: department.id
    },
    create: {
      code: 'CS101',
      title: 'Intro to Computer Science',
      description: 'Basics',
      credits: 3,
      lecturerId: lecturer.id,
      semesterId: semester.id,
      departmentId: department.id
    }
  })

  await prisma.timetableSlot.upsert({
    where: { id: 1 },
    update: { courseId: course.id, day: 'Monday', startTime: '09:00', endTime: '11:00', venue: 'Lab A' },
    create: { courseId: course.id, day: 'Monday', startTime: '09:00', endTime: '11:00', venue: 'Lab A' }
  })

  const assignment = await prisma.assignment.upsert({
    where: { id: 1 },
    update: {
      courseId: course.id,
      title: 'Assignment 1',
      description: 'Write a short algorithm analysis.',
      dueDate: new Date('2026-03-15'),
      createdById: lecturer.id
    },
    create: {
      courseId: course.id,
      title: 'Assignment 1',
      description: 'Write a short algorithm analysis.',
      dueDate: new Date('2026-03-15'),
      createdById: lecturer.id
    }
  })

  await prisma.material.upsert({
    where: { id: 1 },
    update: {
      courseId: course.id,
      title: 'Week 1 Notes',
      url: 'https://portal.techhub.edu/materials/cs101-week1.pdf',
      uploadedBy: lecturer.id
    },
    create: {
      courseId: course.id,
      title: 'Week 1 Notes',
      url: 'https://portal.techhub.edu/materials/cs101-week1.pdf',
      uploadedBy: lecturer.id
    }
  })

  await prisma.courseRegistration.upsert({
    where: { studentId_courseId_semesterId: { studentId: student.id, courseId: course.id, semesterId: semester.id } },
    update: { status: 'registered' },
    create: { studentId: student.id, courseId: course.id, semesterId: semester.id, status: 'registered' }
  })

  await prisma.result.upsert({
    where: { studentId_courseId_semesterId: { studentId: student.id, courseId: course.id, semesterId: semester.id } },
    update: { score: 78, grade: 'B', approved: true },
    create: { studentId: student.id, courseId: course.id, semesterId: semester.id, score: 78, grade: 'B', approved: true }
  })

  const attendanceDate = new Date('2026-02-10')
  const existingAttendance = await prisma.attendance.findFirst({
    where: { studentId: student.id, courseId: course.id, date: attendanceDate }
  })
  if (!existingAttendance) {
    await prisma.attendance.create({
      data: {
        studentId: student.id,
        courseId: course.id,
        markedById: lecturer.id,
        date: attendanceDate,
        present: true
      }
    })
  }

  await prisma.feeStructure.upsert({
    where: { id: 1 },
    update: { level: 'Undergraduate', tuitionPerSemester: 1200, upkeepPerSemester: 450, currency: 'KES' },
    create: { level: 'Undergraduate', tuitionPerSemester: 1200, upkeepPerSemester: 450, currency: 'KES' }
  })

  await prisma.financeAccount.upsert({
    where: { studentId: student.id },
    update: { tuitionBalance: 1200, upkeepBalance: 450 },
    create: { studentId: student.id, tuitionBalance: 1200, upkeepBalance: 450 }
  })

  await prisma.payment.upsert({
    where: { reference: 'MPESA-SEED-001' },
    update: { amount: 150, method: PaymentMethod.MPESA, target: BalanceTarget.TUITION, studentId: student.id },
    create: {
      studentId: student.id,
      amount: 150,
      method: PaymentMethod.MPESA,
      target: BalanceTarget.TUITION,
      reference: 'MPESA-SEED-001'
    }
  })

  await prisma.announcement.upsert({
    where: { id: 1 },
    update: { title: 'Portal Notice', body: 'Welcome to Tech Hub Portal', audience: 'all', authorId: admin.id },
    create: { title: 'Portal Notice', body: 'Welcome to Tech Hub Portal', audience: 'all', authorId: admin.id }
  })

  const existingMessage = await prisma.message.findFirst({
    where: { fromUserId: lecturer.id, toUserId: student.id, body: 'Submit your assignment by Friday.' }
  })
  if (!existingMessage) {
    await prisma.message.create({
      data: { fromUserId: lecturer.id, toUserId: student.id, body: 'Submit your assignment by Friday.' }
    })
  }

  const existingNotification = await prisma.notification.findFirst({
    where: {
      channel: 'EMAIL',
      audience: 'targeted',
      toUserId: student.id,
      sentById: admin.id,
      message: 'Fee payment reminder'
    }
  })
  if (!existingNotification) {
    await prisma.notification.create({
      data: {
        channel: 'EMAIL',
        audience: 'targeted',
        toUserId: student.id,
        sentById: admin.id,
        message: 'Fee payment reminder'
      }
    })
  }

  await prisma.calendarEvent.upsert({
    where: { id: 1 },
    update: { title: 'Semester Opening', date: new Date('2026-01-12'), type: 'academic' },
    create: { title: 'Semester Opening', date: new Date('2026-01-12'), type: 'academic' }
  })

  await prisma.lmsIntegration.upsert({
    where: { id: 1 },
    update: { provider: 'Moodle', enabled: true, url: 'https://moodle.techhub.edu' },
    create: { provider: 'Moodle', enabled: true, url: 'https://moodle.techhub.edu' }
  })

  await prisma.libraryItem.upsert({
    where: { id: 1 },
    update: { title: 'Data Structures Handbook', author: 'S. Wanjiku', available: true },
    create: { title: 'Data Structures Handbook', author: 'S. Wanjiku', available: true }
  })

  await prisma.hostelAllocation.upsert({
    where: { id: 1 },
    update: { studentId: student.id, hostel: 'Hostel A', room: 'B-12' },
    create: { studentId: student.id, hostel: 'Hostel A', room: 'B-12' }
  })

  await prisma.clearanceRequest.upsert({
    where: { id: 1 },
    update: { studentId: student.id, reason: 'General clearance request', status: 'PENDING' },
    create: { studentId: student.id, reason: 'General clearance request', status: 'PENDING' }
  })

  await prisma.alumniProfile.upsert({
    where: { email: student.email },
    update: { name: student.name, userId: student.id, graduationYear: 2029, employmentStatus: 'in-progress' },
    create: { name: student.name, email: student.email, userId: student.id, graduationYear: 2029, employmentStatus: 'in-progress' }
  })

  await prisma.admission.upsert({
    where: { id: 1 },
    update: { name: 'Applicant One', email: 'applicant@techhub.edu', programId: program.id, status: 'PENDING', createdById: admin.id },
    create: { name: 'Applicant One', email: 'applicant@techhub.edu', programId: program.id, status: 'PENDING', createdById: admin.id }
  })

  const existingActivity = await prisma.activityLog.findFirst({
    where: { userId: admin.id, action: 'seed.run' }
  })
  if (!existingActivity) {
    await prisma.activityLog.create({
      data: { userId: admin.id, action: 'seed.run', details: { ok: true, at: new Date().toISOString() } }
    })
  }

  console.log('Prisma seed complete')
}

main()
  .catch((error) => {
    console.error(error)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
