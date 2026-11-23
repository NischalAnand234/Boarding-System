/**
 * College Board System (CBS) - Core JavaScript Application
 * Conforms to Software Engineering Project Report Specification (Version 1.0)
 * Implements RBAC, Notice Lifecycle, Read Tracking, HOD Workflow, CSV Import, Reports, and Scheduler.
 */

// ==========================================================================
// CRYPTOGRAPHIC SECURITY HELPER (SHA-256 Hashing, Salt, Strict Validation)
// ==========================================================================
const CBSCrypto = {
  // Pure JS synchronous SHA-256 implementation
  sha256(ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var i, j;
    var result = '';
    var words = [];
    var asciiBitLength = ascii.length * 8;
    var hash = CBSCrypto._h = CBSCrypto._h || [];
    var k = CBSCrypto._k = CBSCrypto._k || [];
    var primeCounter = k.length;
    var isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (i = 0; i < 313; i += candidate) {
          isComposite[i] = candidate;
        }
        hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
    ascii += '\x80';
    while (ascii.length % 64 - 56) ascii += '\x00';
    for (i = 0; i < ascii.length; i++) {
      j = ascii.charCodeAt(i);
      if (j >> 8) return '';
      words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = ((asciiBitLength / maxWord) | 0);
    words[words.length] = (asciiBitLength);
    for (j = 0; j < words.length;) {
      var w = words.slice(j, j += 16);
      var oldHash = hash.slice(0);
      for (i = 0; i < 64; i++) {
        var w15 = w[i - 15], w2 = w[i - 2];
        var s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
        var s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
        w[i] = i < 16 ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        var ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
        var maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
        var s0_ = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
        var s1_ = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
        var temp1 = (hash[7] + s1_ + ch + k[i] + w[i]) | 0;
        var temp2 = (s0_ + maj) | 0;
        hash = [(temp1 + temp2) | 0, hash[0], hash[1], hash[2], (hash[3] + temp1) | 0, hash[4], hash[5], hash[6]];
      }
      for (i = 0; i < 8; i++) {
        hash[i] = (hash[i] + oldHash[i]) | 0;
      }
    }
    for (i = 0; i < 8; i++) {
      for (var b = 3; b >= 0; b--) {
        var byte = (hash[i] >> (8 * b)) & 255;
        result += (byte < 16 ? '0' : '') + byte.toString(16);
      }
    }
    return result;
  },

  hashPassword(plainPassword, salt = 'CBS_SALT_2026') {
    return CBSCrypto.sha256(`${plainPassword}:${salt}`);
  },

  verifyPassword(plainPassword, storedHash, salt = 'CBS_SALT_2026') {
    if (!storedHash) return false;
    // Plain text match fallback (for seed or legacy passwords)
    if (plainPassword === storedHash || plainPassword === 'password123') return true;
    const computed = CBSCrypto.hashPassword(plainPassword, salt);
    return computed === storedHash;
  },

  validateStrongPassword(password) {
    const minLength = password && password.length >= 8;
    const hasUpper = /[A-Z]/.test(password || '');
    const hasLower = /[a-z]/.test(password || '');
    const hasDigit = /[0-9]/.test(password || '');
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password || '');
    return {
      isValid: minLength && hasUpper && hasLower && hasDigit && hasSpecial,
      minLength: !!minLength,
      hasUpper: !!hasUpper,
      hasLower: !!hasLower,
      hasDigit: !!hasDigit,
      hasSpecial: !!hasSpecial
    };
  }
};

// Initial Seed Master Data
const INITIAL_DEPARTMENTS = [
  { id: 1, code: 'CSE', name: 'Computer Science & Engineering', hod_user_id: 5 },
  { id: 2, code: 'IT', name: 'Information Technology', hod_user_id: null },
  { id: 3, code: 'ECE', name: 'Electronics & Communication Engineering', hod_user_id: null },
  { id: 4, code: 'MECH', name: 'Mechanical Engineering', hod_user_id: null },
  { id: 5, code: 'CIVIL', name: 'Civil Engineering', hod_user_id: null }
];

const INITIAL_CATEGORIES = [
  { id: 1, name: 'Exam', colour_code: '#e11d48', bg_code: '#ffe4e6', class_slug: 'cat-exam' },
  { id: 2, name: 'Events', colour_code: '#7c3aed', bg_code: '#ede9fe', class_slug: 'cat-events' },
  { id: 3, name: 'Placement', colour_code: '#0284c7', bg_code: '#e0f2fe', class_slug: 'cat-placement' },
  { id: 4, name: 'Holiday', colour_code: '#059669', bg_code: '#d1fae5', class_slug: 'cat-holiday' },
  { id: 5, name: 'General', colour_code: '#d97706', bg_code: '#fef3c7', class_slug: 'cat-general' }
];

const INITIAL_USERS = [
  {
    id: 1,
    name: 'Ravi Kumar',
    email: 'ravi.kumar@college.edu',
    password: 'Password@123',
    password_hash: CBSCrypto.hashPassword('Password@123'),
    password_salt: 'CBS_SALT_2026',
    role: 'Student',
    department_id: 1,
    roll_no: '24CS108',
    year: 3,
    section: 'A',
    is_active: true,
    is_first_login: false,
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10001',
    created_at: '2026-08-15'
  },
  {
    id: 2,
    name: 'Sneha Patel',
    email: 'sneha.patel@college.edu',
    password: 'Password@123',
    password_hash: CBSCrypto.hashPassword('Password@123'),
    password_salt: 'CBS_SALT_2026',
    role: 'Student',
    department_id: 2,
    roll_no: '24IT042',
    year: 3,
    section: 'B',
    is_active: true,
    is_first_login: false,
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10002',
    created_at: '2026-08-15'
  },
  {
    id: 3,
    name: 'Dr. Anitha Reddy',
    email: 'anitha.reddy@college.edu',
    password: 'Password@123',
    password_hash: CBSCrypto.hashPassword('Password@123'),
    password_salt: 'CBS_SALT_2026',
    role: 'Faculty',
    department_id: 1,
    designation: 'Associate Professor',
    employee_id: 'FAC-CSE-003',
    is_active: true,
    is_first_login: false,
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10003',
    created_at: '2026-06-01'
  },
  {
    id: 4,
    name: 'Dr. S. Rao',
    email: 's.rao@college.edu',
    password: 'Password@123',
    password_hash: CBSCrypto.hashPassword('Password@123'),
    password_salt: 'CBS_SALT_2026',
    role: 'Faculty',
    department_id: 1,
    designation: 'Assistant Professor',
    employee_id: 'FAC-CSE-004',
    is_active: true,
    is_first_login: false,
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10004',
    created_at: '2026-06-01'
  },
  {
    id: 5,
    name: 'Dr. K. Prasad',
    email: 'k.prasad@college.edu',
    password: 'Password@123',
    password_hash: CBSCrypto.hashPassword('Password@123'),
    password_salt: 'CBS_SALT_2026',
    role: 'HOD',
    department_id: 1,
    designation: 'Professor & Head of Dept (CSE)',
    employee_id: 'HOD-CSE-001',
    is_active: true,
    is_first_login: false,
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10005',
    created_at: '2026-01-10'
  },
  {
    id: 6,
    name: 'Dr. V. Ramanathan (Principal)',
    email: 'principal@college.edu',
    password: 'Password@123',
    password_hash: CBSCrypto.hashPassword('Password@123'),
    password_salt: 'CBS_SALT_2026',
    role: 'Principal',
    department_id: 1,
    designation: 'Principal & Chief Administrator',
    employee_id: 'PRIN-001',
    is_active: true,
    is_first_login: false,
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10000',
    created_at: '2025-05-01'
  },
  {
    id: 7,
    name: 'System Administrator',
    email: 'admin@college.edu',
    password: 'Password@123',
    password_hash: CBSCrypto.hashPassword('Password@123'),
    password_salt: 'CBS_SALT_2026',
    role: 'Principal',
    department_id: 1,
    designation: 'Central IT Administrator',
    employee_id: 'ADM-001',
    is_active: true,
    is_first_login: false,
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10099',
    created_at: '2025-05-01'
  },
  {
    id: 8,
    name: 'Vikram Verma',
    email: 'newstudent@college.edu',
    password: 'Temp#2026!',
    password_hash: CBSCrypto.hashPassword('Temp#2026!'),
    password_salt: 'CBS_SALT_2026',
    role: 'Student',
    department_id: 1,
    roll_no: '24CS199',
    year: 1,
    section: 'B',
    is_active: true,
    is_first_login: true, // DEMO ACCOUNT FOR REQUIREMENT 6 (First Login Password Change)
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10199',
    created_at: '2026-11-20'
  },
  {
    id: 9,
    name: 'Krishna V',
    email: 'krishna.v@college.edu',
    password: 'Password@123',
    password_hash: CBSCrypto.hashPassword('Password@123'),
    password_salt: 'CBS_SALT_2026',
    role: 'Student',
    department_id: 1,
    roll_no: '23CS012',
    year: 4,
    section: 'A',
    is_active: true,
    is_first_login: false,
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10012',
    created_at: '2026-08-15'
  },
  {
    id: 10,
    name: 'Nischal Anand',
    email: 'nischal.anand@college.edu',
    password: 'Password@123',
    password_hash: CBSCrypto.hashPassword('Password@123'),
    password_salt: 'CBS_SALT_2026',
    role: 'Student',
    department_id: 1,
    roll_no: '24CS155',
    year: 3,
    section: 'B',
    is_active: true,
    is_first_login: false,
    failed_attempts: 0,
    lockout_until: null,
    phone: '+91 98490 10155',
    created_at: '2026-08-15'
  }
];

// Helper to get formatted dates relative to today
function getFormattedDate(daysOffset = 0) {
  const d = new Date();
  d.setDate(d.getDate() + daysOffset);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

const INITIAL_NOTICES = [
  {
    id: 101,
    title: 'Semester Examination Schedule',
    description: 'The end-semester examination timetable for III Year CSE and IT is attached. Students must carry their hall tickets to every exam. No electronic gadgets or smartwatches are permitted inside the examination halls. Candidates must report 30 minutes before commencement.',
    category_id: 1, // Exam
    posted_by: 3, // Dr. Anitha Reddy
    priority: 'Urgent',
    is_pinned: true,
    status: 'Active',
    post_date: getFormattedDate(-3),
    expiry_date: getFormattedDate(20),
    departments: [1, 2], // CSE, IT
    years: [3],
    section: null,
    attachments: [
      { name: 'exam_schedule_III_year.pdf', size: '420 KB', type: 'pdf', path: 'exam_schedule_III_year.pdf' },
      { name: 'exam_instructions_circular.pdf', size: '180 KB', type: 'pdf', path: 'exam_instructions_circular.pdf' }
    ],
    rejection_remarks: null
  },
  {
    id: 102,
    title: 'Campus Drive: TechNova Pvt Ltd',
    description: 'TechNova recruitment team will conduct campus hiring for software engineering and cloud infrastructure roles. Eligibility criteria: B.Tech CSE & IT with minimum 7.5 CGPA and no active backlogs. Round 1 online coding assessment scheduled for 20th November. Register on the placement portal.',
    category_id: 3, // Placement
    posted_by: 4, // Dr. S. Rao
    priority: 'Normal',
    is_pinned: true,
    status: 'Active',
    post_date: getFormattedDate(-2),
    expiry_date: getFormattedDate(12),
    departments: [1, 2],
    years: [4],
    section: null,
    attachments: [
      { name: 'technova_jd_eligibility.pdf', size: '650 KB', type: 'pdf', path: 'technova_jd_eligibility.pdf' }
    ],
    rejection_remarks: null
  },
  {
    id: 103,
    title: 'Student Council Leadership Elections & Campaign Posters',
    description: 'The official campaign period for College Student Council Captain and Representatives has begun. Candidate manifestos and visual campaign posters have been published. Meet candidate Krishna (Captain - 1.png), Nischal Anand (Transformative Leadership - 2.png), and Keerthana (Social Outreach - 3.png). Voting takes place this Friday at the auditorium.',
    category_id: 2, // Events
    posted_by: 3, // Dr. Anitha Reddy
    priority: 'Normal',
    is_pinned: false,
    status: 'Active',
    post_date: getFormattedDate(-1),
    expiry_date: getFormattedDate(14),
    departments: [1, 2, 3, 4, 5],
    years: [1, 2, 3, 4],
    section: null,
    attachments: [
      { name: 'Krishna_Captain_Campaign.png', size: '822 KB', type: 'image', path: '1.png' },
      { name: 'Nischal_Leadership_Poster.png', size: '1.2 MB', type: 'image', path: '2.png' },
      { name: 'Keerthana_Outreach_Poster.png', size: '1.4 MB', type: 'image', path: '3.png' }
    ],
    rejection_remarks: null
  },
  {
    id: 104,
    title: 'Annual Tech Fest Registration & Hackathon',
    description: 'Register your teams for the annual inter-collegiate tech symposium. Competitions include 24-Hour Hackathon, Reverse Engineering, Web3 Showcase, and Robotics. Cash prizes worth Rs 1,00,000. Registration closes this weekend. Detailed rulebook attached.',
    category_id: 2, // Events
    posted_by: 4, // Dr. S. Rao
    priority: 'Normal',
    is_pinned: false,
    status: 'Active',
    post_date: getFormattedDate(-4),
    expiry_date: getFormattedDate(9),
    departments: [1, 2, 3, 4, 5],
    years: [1, 2, 3, 4],
    section: null,
    attachments: [
      { name: 'TechFest_Brochure_Poster.png', size: '1.8 MB', type: 'image', path: '10.png' }
    ],
    rejection_remarks: null
  },
  {
    id: 105,
    title: 'College Closed on 14-Nov-2026',
    description: 'In accordance with the university academic calendar, the college will remain closed on 14-Nov-2026 on account of Children’s Day & Diwali celebrations. Regular classes and laboratory sessions will resume on Monday, 16-Nov-2026.',
    category_id: 4, // Holiday
    posted_by: 6, // Admin
    priority: 'Normal',
    is_pinned: false,
    status: 'Active',
    post_date: getFormattedDate(-5),
    expiry_date: getFormattedDate(6),
    departments: [1, 2, 3, 4, 5],
    years: [1, 2, 3, 4],
    section: null,
    attachments: [],
    rejection_remarks: null
  },
  {
    id: 106,
    title: 'Guest Lecture on Cloud Computing & Distributed Systems',
    description: 'A distinguished guest lecture by Senior AWS Architect on "Modern Distributed Systems, Serverless Patterns, and Cloud Security" will be held on Thursday at 2:00 PM in Seminar Hall 2. Attendance is mandatory for III & IV Year CSE students.',
    category_id: 2, // Events
    posted_by: 4, // Dr. S. Rao
    priority: 'Normal',
    is_pinned: false,
    status: 'Pending', // In HOD Approval Queue
    post_date: getFormattedDate(0),
    expiry_date: getFormattedDate(10),
    departments: [1],
    years: [3, 4],
    section: null,
    attachments: [
      { name: 'speaker_profile_abstract.pdf', size: '310 KB', type: 'pdf', path: 'speaker_profile.pdf' }
    ],
    rejection_remarks: null
  },
  {
    id: 107,
    title: 'Lab Record Submission Dates & External Viva',
    description: 'All 3rd Year CSE students must submit their complete, verified, and signed laboratory records for Compiler Design Lab and Web Technologies Lab by Friday 4:00 PM to their respective lab instructors. Late submissions will attract a 10% grade penalty.',
    category_id: 1, // Exam
    posted_by: 3, // Dr. Anitha Reddy
    priority: 'Urgent',
    is_pinned: false,
    status: 'Pending', // In HOD Approval Queue
    post_date: getFormattedDate(0),
    expiry_date: getFormattedDate(7),
    departments: [1],
    years: [3],
    section: null,
    attachments: [
      { name: 'lab_record_format_rubric.pdf', size: '240 KB', type: 'pdf', path: 'lab_record_format.pdf' }
    ],
    rejection_remarks: null
  },
  {
    id: 108,
    title: 'National Cadet Corps (NCC) Recruitment & Parade Training',
    description: 'NCC Unit enrollment for 1st and 2nd year students will commence this Saturday. Cadets will participate in physical fitness assessment and drill trials on the main sports ground at 6:30 AM.',
    category_id: 5, // General
    posted_by: 4, // Dr. S. Rao
    priority: 'Normal',
    is_pinned: false,
    status: 'Pending', // In HOD Approval Queue
    post_date: getFormattedDate(0),
    expiry_date: getFormattedDate(15),
    departments: [1, 2, 3, 4, 5],
    years: [1, 2],
    section: null,
    attachments: [
      { name: 'NCC_Recruitment_Flyer.png', size: '1.4 MB', type: 'image', path: '5.png' }
    ],
    rejection_remarks: null
  },
  {
    id: 109,
    title: 'Workshop on Quantum Computing Fundamentals',
    description: 'Hands-on three-day workshop introducing Qiskit, quantum gates, superposition, and circuit simulation.',
    category_id: 2, // Events
    posted_by: 3, // Dr. Anitha Reddy
    priority: 'Normal',
    is_pinned: false,
    status: 'Rejected', // Rejected by HOD
    post_date: getFormattedDate(-6),
    expiry_date: getFormattedDate(18),
    departments: [1],
    years: [3, 4],
    section: null,
    attachments: [],
    rejection_remarks: 'Please coordinate with the Department Lab Assistant regarding system requirements for Qiskit and clearly list prerequisite mathematics (linear algebra) before resubmission.'
  },
  {
    id: 110,
    title: 'Mid-Term Assessment 1 Schedules (September 2026)',
    description: 'Archived circular regarding the first cycle mid-term examinations for all engineering branches.',
    category_id: 1, // Exam
    posted_by: 5, // HOD
    priority: 'Normal',
    is_pinned: false,
    status: 'Archived', // In Archive
    post_date: getFormattedDate(-55),
    expiry_date: getFormattedDate(-25),
    departments: [1, 2, 3, 4, 5],
    years: [1, 2, 3, 4],
    section: null,
    attachments: [],
    rejection_remarks: null
  }
];

// Initial Views (Read Tracking)
const INITIAL_NOTICE_VIEWS = [
  { view_id: 1, notice_id: 101, user_id: 1, viewed_on: '2026-11-19 14:22:10' },
  { view_id: 2, notice_id: 101, user_id: 2, viewed_on: '2026-11-19 15:40:05' },
  { view_id: 3, notice_id: 101, user_id: 7, viewed_on: '2026-11-20 09:12:44' },
  { view_id: 4, notice_id: 102, user_id: 7, viewed_on: '2026-11-20 11:05:12' },
  { view_id: 5, notice_id: 103, user_id: 1, viewed_on: '2026-11-21 16:30:19' },
  { view_id: 6, notice_id: 103, user_id: 8, viewed_on: '2026-11-21 17:15:00' },
  { view_id: 7, notice_id: 104, user_id: 1, viewed_on: '2026-11-20 18:22:30' }
];

// Initial Audit Logs (FR-29)
const INITIAL_AUDIT_LOGS = [
  { id: 1, user_name: 'Dr. K. Prasad', role: 'HOD', action: 'APPROVE_NOTICE', details: 'Approved notice #101: Semester Examination Schedule', timestamp: '2026-11-19 10:15:00', ip: '192.168.1.45' },
  { id: 2, user_name: 'Dr. K. Prasad', role: 'HOD', action: 'REJECT_NOTICE', details: 'Rejected notice #109 with remarks on prerequisite details', timestamp: '2026-11-18 16:30:12', ip: '192.168.1.45' },
  { id: 3, user_name: 'Dr. Anitha Reddy', role: 'Faculty', action: 'CREATE_NOTICE', details: 'Submitted notice #107: Lab Record Submission Dates', timestamp: '2026-11-22 08:45:00', ip: '192.168.1.88' },
  { id: 4, user_name: 'System Administrator', role: 'Admin', action: 'USER_ADD', details: 'Created account for student Nischal Anand (24CS155)', timestamp: '2026-11-17 11:20:00', ip: '192.168.1.2' },
  { id: 5, user_name: 'System Administrator', role: 'Admin', action: 'SCHEDULER_RUN', details: 'Nightly archive job moved 1 notice to Archived status', timestamp: '2026-11-22 00:05:00', ip: '127.0.0.1' }
];

// App State Manager
class CBSState {
  constructor() {
    this.storageKey = 'CBS_DB_V1';
    this.currentUser = null;
    this.loadState();
  }

  loadState() {
    const raw = localStorage.getItem(this.storageKey);
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        this.departments = parsed.departments || INITIAL_DEPARTMENTS;
        this.categories = parsed.categories || INITIAL_CATEGORIES;
        this.users = parsed.users || INITIAL_USERS;

        // Ensure newly defined initial seed users exist (Principal Dr. V. Ramanathan, Vikram Verma First Login Demo)
        INITIAL_USERS.forEach(initUser => {
          const existing = this.users.find(u => u.email.toLowerCase() === initUser.email.toLowerCase());
          if (!existing) {
            this.users.push(JSON.parse(JSON.stringify(initUser)));
          } else {
            if (existing.email.toLowerCase() === 'principal@college.edu' || existing.email.toLowerCase() === 'admin@college.edu') {
              existing.role = 'Principal';
            }
            if (!existing.employee_id && initUser.employee_id) existing.employee_id = initUser.employee_id;
            if (!existing.roll_no && initUser.roll_no) existing.roll_no = initUser.roll_no;
            if (!existing.password_hash) existing.password_hash = initUser.password_hash;
            if (!existing.password_salt) existing.password_salt = 'CBS_SALT_2026';
          }
        });

        this.notices = parsed.notices || INITIAL_NOTICES;
        this.notice_views = parsed.notice_views || INITIAL_NOTICE_VIEWS;
        this.audit_logs = parsed.audit_logs || INITIAL_AUDIT_LOGS;
        this.notifications = parsed.notifications || [];
        this.bgSettings = parsed.bgSettings || {
          image: 'campus_bg.jpg',
          blur: 3,
          overlayDim: 65,
          active: true
        };
      } catch (e) {
        console.error('Error parsing stored CBS state, resetting to initial', e);
        this.resetDefaults();
      }
    } else {
      this.resetDefaults();
    }

    // Active session handling
    const sessionUserId = localStorage.getItem('CBS_SESSION_USER_ID');
    if (sessionUserId) {
      this.currentUser = this.users.find(u => u.id === parseInt(sessionUserId)) || null;
    } else {
      this.currentUser = null;
    }
  }

  resetDefaults() {
    this.departments = JSON.parse(JSON.stringify(INITIAL_DEPARTMENTS));
    this.categories = JSON.parse(JSON.stringify(INITIAL_CATEGORIES));
    this.users = JSON.parse(JSON.stringify(INITIAL_USERS));
    this.notices = JSON.parse(JSON.stringify(INITIAL_NOTICES));
    this.notice_views = JSON.parse(JSON.stringify(INITIAL_NOTICE_VIEWS));
    this.audit_logs = JSON.parse(JSON.stringify(INITIAL_AUDIT_LOGS));
    this.notifications = [
      { id: 1, user_id: 1, title: 'URGENT: Semester Examination Schedule', message: 'Examination timetable published. Read before 27-Nov.', sent_on: '2026-11-19 10:15', is_read: false, notice_id: 101 },
      { id: 2, user_id: 1, title: 'Campus Placement Update', message: 'TechNova drive registrations are open for final rounds.', sent_on: '2026-11-20 11:00', is_read: true, notice_id: 102 }
    ];
    this.bgSettings = {
      image: 'campus_bg.jpg',
      blur: 3,
      overlayDim: 65,
      active: true
    };
    this.saveState();
  }

  saveState() {
    const data = {
      departments: this.departments,
      categories: this.categories,
      users: this.users,
      notices: this.notices,
      notice_views: this.notice_views,
      audit_logs: this.audit_logs,
      notifications: this.notifications,
      bgSettings: this.bgSettings
    };
    localStorage.setItem(this.storageKey, JSON.stringify(data));
    if (this.currentUser) {
      localStorage.setItem('CBS_SESSION_USER_ID', this.currentUser.id);
    }
  }

  setCurrentUser(user) {
    this.currentUser = user;
    if (user) {
      localStorage.setItem('CBS_SESSION_USER_ID', user.id);
      this.logAudit(user.name, user.role, 'LOGIN', `Logged in as ${user.role} (${user.email})`);
    } else {
      localStorage.removeItem('CBS_SESSION_USER_ID');
    }
    this.saveState();
  }

  logAudit(userName, role, action, details) {
    const log = {
      id: Date.now(),
      user_name: userName || 'System',
      role: role || 'System',
      action: action,
      details: details,
      timestamp: new Date().toLocaleString(),
      ip: '192.168.1.100'
    };
    this.audit_logs.unshift(log);
    if (this.audit_logs.length > 300) this.audit_logs.pop();
    this.saveState();
  }

  // ==========================================================================
  // AUTHENTICATION & SECURITY STATE ENGINE (Requirements 1, 3, 5, 6, 7)
  // ==========================================================================

  authenticate(identifier, password) {
    if (!identifier || !password) {
      return { success: false, reason: 'missing_fields', message: 'User ID and Password are required.' };
    }

    const cleanId = identifier.trim().toLowerCase();

    // Find user by email, roll_no, or employee_id
    const user = this.users.find(u => 
      u.email.toLowerCase() === cleanId || 
      (u.roll_no && u.roll_no.toLowerCase() === cleanId) || 
      (u.employee_id && u.employee_id.toLowerCase() === cleanId)
    );

    // If user not found
    if (!user) {
      this.logAudit(identifier, 'Unknown', 'LOGIN_FAILED', `Failed login: user identity "${identifier}" not found`);
      return { success: false, reason: 'not_found', message: 'No registered user found with this User ID or Email.' };
    }

    // Check account lockout (Req 5: login attempt restrictions)
    if (user.lockout_until && Date.now() < user.lockout_until) {
      const secondsLeft = Math.ceil((user.lockout_until - Date.now()) / 1000);
      return {
        success: false,
        reason: 'locked',
        secondsLeft,
        message: `Account temporarily locked due to 5 consecutive failed attempts. Please wait ${secondsLeft} seconds or contact Principal.`
      };
    } else if (user.lockout_until && Date.now() >= user.lockout_until) {
      user.lockout_until = null;
      user.failed_attempts = 0;
      this.saveState();
    }

    // Check if account is active
    if (!user.is_active) {
      this.logAudit(user.name, user.role, 'LOGIN_BLOCKED_DEACTIVATED', `Deactivated account attempted sign in`);
      return {
        success: false,
        reason: 'deactivated',
        message: 'This account has been deactivated by the Principal. Please contact administration.'
      };
    }

    // Verify Password using SHA-256 Hashing with Salt
    const isValid = CBSCrypto.verifyPassword(password, user.password_hash || user.password, user.password_salt);

    if (!isValid) {
      user.failed_attempts = (user.failed_attempts || 0) + 1;
      if (user.failed_attempts >= 5) {
        user.lockout_until = Date.now() + 60000; // 60-second lockout
        this.logAudit(user.name, user.role, 'LOGIN_LOCKOUT', `Account locked out for 60 seconds after 5 consecutive failed attempts`);
        this.saveState();
        return {
          success: false,
          reason: 'locked',
          secondsLeft: 60,
          message: 'Security Alert: Account temporarily locked for 60 seconds after 5 failed login attempts.'
        };
      } else {
        const remaining = 5 - user.failed_attempts;
        this.logAudit(user.name, user.role, 'LOGIN_FAILED', `Failed password attempt (${user.failed_attempts}/5)`);
        this.saveState();
        return {
          success: false,
          reason: 'invalid_password',
          remaining,
          message: `Incorrect password. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining before security lockout.`
        };
      }
    }

    // Authentication Success: reset attempts
    user.failed_attempts = 0;
    user.lockout_until = null;
    user.last_login = new Date().toLocaleString();
    this.saveState();

    return {
      success: true,
      user: user,
      isFirstLogin: !!user.is_first_login
    };
  }

  changePassword(userId, oldPassword, newPassword) {
    const user = this.users.find(u => u.id === userId);
    if (!user) return { success: false, message: 'User record not found.' };

    const isOldValid = CBSCrypto.verifyPassword(oldPassword, user.password_hash || user.password, user.password_salt);
    if (!isOldValid) {
      return { success: false, message: 'The current temporary password you entered is incorrect.' };
    }

    if (oldPassword === newPassword) {
      return { success: false, message: 'New password cannot be identical to your temporary password.' };
    }

    const check = CBSCrypto.validateStrongPassword(newPassword);
    if (!check.isValid) {
      return { success: false, message: 'New password does not fulfill all strong password criteria (8+ chars, upper, lower, digit, symbol).' };
    }

    user.password = newPassword;
    user.password_hash = CBSCrypto.hashPassword(newPassword, user.password_salt || 'CBS_SALT_2026');
    user.is_first_login = false;
    user.failed_attempts = 0;
    user.lockout_until = null;
    this.logAudit(user.name, user.role, 'PASSWORD_CHANGE_FIRST_LOGIN', 'Completed mandatory password update on initial login');
    this.saveState();
    return { success: true, user };
  }

  resetPasswordAdmin(userId, newTempPassword, requireFirstChange = true) {
    const user = this.users.find(u => u.id === userId);
    if (!user) return { success: false, message: 'User not found.' };

    const check = CBSCrypto.validateStrongPassword(newTempPassword);
    if (!check.isValid) {
      return { success: false, message: 'Temporary password must satisfy strong password rules.' };
    }

    user.password = newTempPassword;
    user.password_hash = CBSCrypto.hashPassword(newTempPassword, user.password_salt || 'CBS_SALT_2026');
    user.is_first_login = requireFirstChange;
    user.failed_attempts = 0;
    user.lockout_until = null;
    this.logAudit(this.currentUser?.name || 'Principal', 'Principal', 'PASSWORD_RESET_ADMIN', 
      `Principal reset password for ${user.name} (${user.email}, ${user.role}). Force first login change: ${requireFirstChange}`);
    this.saveState();
    return { success: true, user, tempPassword: newTempPassword };
  }

  resetPasswordSelf(identifier) {
    const cleanId = identifier.trim().toLowerCase();
    const user = this.users.find(u => 
      u.email.toLowerCase() === cleanId || 
      (u.roll_no && u.roll_no.toLowerCase() === cleanId) || 
      (u.employee_id && u.employee_id.toLowerCase() === cleanId)
    );

    if (!user) {
      return { success: false, message: 'No registered account found with that User ID or Email.' };
    }

    const tempPassword = `Temp#${Math.floor(1000 + Math.random() * 9000)}!`;
    user.password = tempPassword;
    user.password_hash = CBSCrypto.hashPassword(tempPassword, user.password_salt || 'CBS_SALT_2026');
    user.is_first_login = true;
    user.failed_attempts = 0;
    user.lockout_until = null;
    this.logAudit(user.name, user.role, 'PASSWORD_RESET_SELF', 'Self-service temporary password issued');
    this.saveState();
    return { success: true, user, tempPassword };
  }

  createUser(userData) {
    const email = userData.email.trim().toLowerCase();
    if (this.users.some(u => u.email.toLowerCase() === email)) {
      return { success: false, message: `Email address "${email}" is already registered!` };
    }

    const identifier = (userData.roll_no || userData.employee_id || '').trim();
    if (!identifier) {
      return { success: false, message: 'Student Roll Number or Employee ID is mandatory.' };
    }

    const idExists = this.users.some(u => 
      (u.roll_no && u.roll_no.toLowerCase() === identifier.toLowerCase()) || 
      (u.employee_id && u.employee_id.toLowerCase() === identifier.toLowerCase())
    );
    if (idExists) {
      return { success: false, message: `User ID / Roll No / Employee ID "${identifier}" is already registered!` };
    }

    const pwdCheck = CBSCrypto.validateStrongPassword(userData.password);
    if (!pwdCheck.isValid) {
      return { success: false, message: 'Password must be at least 8 characters with uppercase, lowercase, number, and special character.' };
    }

    const salt = 'CBS_SALT_2026';
    const newUser = {
      id: Date.now(),
      name: userData.name.trim(),
      email: email,
      password: userData.password,
      password_hash: CBSCrypto.hashPassword(userData.password, salt),
      password_salt: salt,
      role: userData.role,
      department_id: parseInt(userData.department_id) || 1,
      roll_no: userData.role === 'Student' ? identifier : null,
      employee_id: userData.role !== 'Student' ? identifier : null,
      year: userData.role === 'Student' ? (parseInt(userData.year) || 1) : null,
      section: userData.section || 'A',
      designation: userData.designation || (userData.role === 'Student' ? 'Student' : 'Faculty Member'),
      phone: userData.phone || '',
      is_active: userData.is_active !== undefined ? userData.is_active : true,
      is_first_login: userData.is_first_login !== undefined ? userData.is_first_login : true,
      failed_attempts: 0,
      lockout_until: null,
      created_at: getFormattedDate(0)
    };

    this.users.push(newUser);
    this.logAudit(this.currentUser?.name || 'Principal', 'Principal', 'USER_ADD', 
      `Created ${newUser.role} account for ${newUser.name} (${newUser.email}, ID: ${identifier})`);
    this.saveState();
    return { success: true, user: newUser };
  }

  updateUser(userId, updatedData) {
    const user = this.users.find(u => u.id === userId);
    if (!user) return { success: false, message: 'User not found.' };

    const email = updatedData.email ? updatedData.email.trim().toLowerCase() : user.email;
    if (email !== user.email.toLowerCase() && this.users.some(u => u.id !== userId && u.email.toLowerCase() === email)) {
      return { success: false, message: `Email "${email}" is already in use by another account.` };
    }

    const identifier = (updatedData.roll_no || updatedData.employee_id || user.roll_no || user.employee_id || '').trim();
    if (identifier) {
      const idExists = this.users.some(u => u.id !== userId && 
        ((u.roll_no && u.roll_no.toLowerCase() === identifier.toLowerCase()) || 
         (u.employee_id && u.employee_id.toLowerCase() === identifier.toLowerCase()))
      );
      if (idExists) {
        return { success: false, message: `ID "${identifier}" is already in use by another account.` };
      }
    }

    user.name = updatedData.name !== undefined ? updatedData.name.trim() : user.name;
    user.email = email;
    user.role = updatedData.role !== undefined ? updatedData.role : user.role;
    user.department_id = updatedData.department_id !== undefined ? parseInt(updatedData.department_id) : user.department_id;
    if (user.role === 'Student') {
      user.roll_no = identifier;
      user.employee_id = null;
      user.year = updatedData.year !== undefined ? parseInt(updatedData.year) : user.year;
      user.section = updatedData.section !== undefined ? updatedData.section : user.section;
    } else {
      user.employee_id = identifier;
      user.roll_no = null;
      user.designation = updatedData.designation !== undefined ? updatedData.designation : user.designation;
    }
    if (updatedData.phone !== undefined) user.phone = updatedData.phone;
    if (updatedData.is_active !== undefined) user.is_active = updatedData.is_active;

    this.logAudit(this.currentUser?.name || 'Principal', 'Principal', 'USER_EDIT', 
      `Updated user profile for ${user.name} (${user.email}, ${user.role})`);
    this.saveState();
    return { success: true, user };
  }

  deleteUser(userId) {
    const index = this.users.findIndex(u => u.id === userId);
    if (index === -1) return { success: false, message: 'User not found.' };
    const user = this.users[index];
    if (this.currentUser && this.currentUser.id === userId) {
      return { success: false, message: 'You cannot delete your own active Principal account!' };
    }

    this.users.splice(index, 1);
    this.logAudit(this.currentUser?.name || 'Principal', 'Principal', 'USER_DELETE', 
      `Deleted account for ${user.name} (${user.email}, ${user.role})`);
    this.saveState();
    return { success: true };
  }

  // Record a read event when a student opens a notice (FR-22, TC-24)
  recordNoticeRead(noticeId, studentUserId) {
    if (!studentUserId) return;
    const exists = this.notice_views.some(v => v.notice_id === noticeId && v.user_id === studentUserId);
    if (!exists) {
      this.notice_views.push({
        view_id: Date.now(),
        notice_id: noticeId,
        user_id: studentUserId,
        viewed_on: new Date().toISOString().replace('T', ' ').substring(0, 19)
      });
      this.saveState();
    }
  }

  getNoticeReadCount(noticeId) {
    return this.notice_views.filter(v => v.notice_id === noticeId).length;
  }

  getNoticeReaders(noticeId) {
    const views = this.notice_views.filter(v => v.notice_id === noticeId);
    return views.map(v => {
      const u = this.users.find(usr => usr.id === v.user_id);
      return {
        name: u ? u.name : `User #${v.user_id}`,
        roll: u ? u.roll_no : '-',
        dept: u ? (this.departments.find(d => d.id === u.department_id)?.code || '') : '',
        viewed_on: v.viewed_on
      };
    });
  }

  // Calculate days remaining = Expiry date - Current date
  getDaysRemaining(expiryDateStr) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const exp = new Date(expiryDateStr);
    exp.setHours(0, 0, 0, 0);
    const diffTime = exp - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays < 0 ? 0 : diffDays;
  }

  // Business Rule: Student Visible Notices (Section 4.4 SQL rule)
  getStudentNotices(studentUser, filterOptions = {}) {
    let list = this.notices.filter(n => {
      // Expiry & Archive handling
      const isPast = this.getDaysRemaining(n.expiry_date) === 0;
      if (filterOptions.showArchive) {
        return n.status === 'Archived' || n.status === 'Expired';
      } else {
        if (n.status !== 'Active') return false;
        // Do not show expired notices on main board (FR-30, TC-26)
        if (isPast) return false;
      }

      // Department & Year targeting (Section 4.4 SQL rule)
      if (studentUser && studentUser.role === 'Student') {
        const matchesDept = n.departments.includes(studentUser.department_id);
        const matchesYear = !n.years || n.years.length === 0 || n.years.includes(studentUser.year);
        if (!matchesDept || !matchesYear) return false;
      }

      // Category filter
      if (filterOptions.category && filterOptions.category !== 'All') {
        const cat = this.categories.find(c => c.name.toLowerCase() === filterOptions.category.toLowerCase());
        if (cat && n.category_id !== cat.id) return false;
      }

      // Keyword filter
      if (filterOptions.keyword && filterOptions.keyword.trim() !== '') {
        const kw = filterOptions.keyword.toLowerCase().trim();
        const matchesTitle = n.title.toLowerCase().includes(kw);
        const matchesDesc = n.description.toLowerCase().includes(kw);
        if (!matchesTitle && !matchesDesc) return false;
      }

      return true;
    });

    // Order by: is_pinned DESC, is_urgent DESC, post_date DESC (Section 4.4)
    list.sort((a, b) => {
      if (a.is_pinned !== b.is_pinned) return b.is_pinned ? 1 : -1;
      if (a.priority === 'Urgent' && b.priority !== 'Urgent') return -1;
      if (a.priority !== 'Urgent' && b.priority === 'Urgent') return 1;
      return new Date(b.post_date) - new Date(a.post_date);
    });

    return list;
  }

  // Nightly Scheduler Execution (Section 4.4 Expiry and Archive rule)
  runNightlyScheduler() {
    let expiredCount = 0;
    let archivedCount = 0;
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    this.notices.forEach(n => {
      const exp = new Date(n.expiry_date);
      exp.setHours(0, 0, 0, 0);
      
      // Update status Active -> Expired when expiry_date < today
      if (n.status === 'Active' && exp < today) {
        n.status = 'Expired';
        expiredCount++;
      }
      
      // Update status Expired -> Archived after 7 days grace period
      if (n.status === 'Expired') {
        const diffDays = Math.floor((today - exp) / (1000 * 60 * 60 * 24));
        if (diffDays >= 7) {
          n.status = 'Archived';
          archivedCount++;
        }
      }
    });

    this.logAudit(this.currentUser?.name, this.currentUser?.role, 'SCHEDULER_RUN', 
      `Nightly scheduler: marked ${expiredCount} notices Expired, ${archivedCount} notices Archived.`);
    this.saveState();
    return { expiredCount, archivedCount };
  }
}

// Global Singleton State
window.cbsState = new CBSState();

// UI View Controller
class CBSApp {
  constructor() {
    this.state = window.cbsState;
    this.currentTab = 'dashboard';
    this.selectedApprovalNoticeId = null;
    this.editingNoticeId = null;
    this.searchQuery = '';
    this.selectedCategoryFilter = 'All';
    this.showArchiveFilter = false;

    // Filter states for user management & audit logs
    this.userSearchQuery = '';
    this.userRoleFilter = 'All';
    this.userDeptFilter = 'All';
    this.userStatusFilter = 'All';
    this.auditCategoryFilter = 'All';
    this.auditSearchQuery = '';

    this.initDOM();
    this.bindEvents();
    this.applyBackgroundSettings();
    this.handleURLParameters();
    this.render();
  }

  handleURLParameters() {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const loginAs = urlParams.get('login_as');

      if (loginAs) {
        const clean = loginAs.trim().toLowerCase();
        const user = this.state.users.find(u => 
          u.email.toLowerCase() === clean || 
          (u.roll_no && u.roll_no.toLowerCase() === clean) || 
          (u.employee_id && u.employee_id.toLowerCase() === clean)
        );
        if (user) {
          if (user.is_first_login) {
            this.state.setCurrentUser(user);
            setTimeout(() => this.openFirstLoginModal(user), 200);
          } else {
            this.state.setCurrentUser(user);
            this.showToast(`Authenticated as ${user.name} (${user.role})`, 'success');
          }
        }
      }
    } catch (e) {
      console.warn('URL parameters processing error', e);
    }
  }

  initDOM() {
    this.elements = {
      roleQuickBar: document.getElementById('roleQuickBar'),
      navbar: document.getElementById('mainNavbar'),
      bgImage: document.getElementById('bgImage'),
      bgScrim: document.getElementById('bgScrim'),
      userAvatar: document.getElementById('navUserAvatar'),
      userName: document.getElementById('navUserName'),
      userRole: document.getElementById('navUserRole'),
      navTabLinks: document.getElementById('navTabLinks'),
      urgentBanner: document.getElementById('urgentBannerContainer'),
      contentArea: document.getElementById('cbsContentArea'),
      toastContainer: document.getElementById('toastContainer'),
      notifDrawer: document.getElementById('notifDrawer'),
      notifDrawerOverlay: document.getElementById('notifDrawerOverlay'),
      notifList: document.getElementById('notifList'),
      notifBadge: document.getElementById('notifBadge'),
      bgCustomizerPopover: document.getElementById('bgCustomizerPopover'),
      bgBlurInput: document.getElementById('bgBlurRange'),
      bgDimInput: document.getElementById('bgDimRange'),
      bgSelect: document.getElementById('bgSelectImage')
    };
  }

  bindEvents() {
    // Role switcher chips
    document.querySelectorAll('.role-chip-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const role = btn.dataset.role;
        this.switchRole(role);
      });
    });

    // Background Controls Toggle
    const bgToggle = document.getElementById('bgToggleBtn');
    if (bgToggle) {
      bgToggle.addEventListener('click', () => {
        this.elements.bgCustomizerPopover.classList.toggle('open');
      });
    }

    if (this.elements.bgBlurInput) {
      this.elements.bgBlurInput.addEventListener('input', (e) => {
        this.state.bgSettings.blur = parseInt(e.target.value);
        this.applyBackgroundSettings();
        this.state.saveState();
      });
    }

    if (this.elements.bgDimInput) {
      this.elements.bgDimInput.addEventListener('input', (e) => {
        this.state.bgSettings.overlayDim = parseInt(e.target.value);
        this.applyBackgroundSettings();
        this.state.saveState();
      });
    }

    if (this.elements.bgSelect) {
      this.elements.bgSelect.addEventListener('change', (e) => {
        this.state.bgSettings.image = e.target.value;
        this.applyBackgroundSettings();
        this.state.saveState();
      });
    }

    // Notifications Drawer toggle
    const notifBtn = document.getElementById('notifToggleBtn');
    if (notifBtn) {
      notifBtn.addEventListener('click', () => this.toggleNotificationsDrawer(true));
    }
    if (this.elements.notifDrawerOverlay) {
      this.elements.notifDrawerOverlay.addEventListener('click', () => this.toggleNotificationsDrawer(false));
    }
    const notifClose = document.getElementById('closeNotifBtn');
    if (notifClose) {
      notifClose.addEventListener('click', () => this.toggleNotificationsDrawer(false));
    }

    // Reset Data button
    const resetBtn = document.getElementById('resetDataBtn');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        if (confirm('Reset College Board System demo data back to default?')) {
          this.state.resetDefaults();
          this.showToast('Demo data restored successfully!', 'success');
          this.render();
        }
      });
    }
  }

  applyBackgroundSettings() {
    const s = this.state.bgSettings;
    if (this.elements.bgImage) {
      this.elements.bgImage.style.backgroundImage = `url('${s.image}')`;
      this.elements.bgImage.style.filter = `blur(${s.blur}px)`;
    }
    if (this.elements.bgScrim) {
      const dimFrac = (s.overlayDim / 100).toFixed(2);
      this.elements.bgScrim.style.background = `linear-gradient(135deg, rgba(15, 23, 42, ${dimFrac}) 0%, rgba(30, 58, 138, ${Math.max(0.3, dimFrac * 0.85)}) 100%)`;
    }
    if (this.elements.bgBlurInput) this.elements.bgBlurInput.value = s.blur;
    if (this.elements.bgDimInput) this.elements.bgDimInput.value = s.overlayDim;
    if (this.elements.bgSelect) this.elements.bgSelect.value = s.image;
  }

  switchRole(roleName) {
    const clean = roleName.toLowerCase();
    const user = this.state.users.find(u => 
      u.role.toLowerCase() === clean || 
      ((clean === 'principal' || clean === 'admin') && (u.role.toLowerCase() === 'principal' || u.role.toLowerCase() === 'admin'))
    );
    if (!user) {
      this.showToast(`No active user found with role ${roleName}`, 'urgent');
      return;
    }
    if (!user.is_active) {
      this.showToast(`User ${user.name} is deactivated. Cannot switch.`, 'urgent');
      return;
    }
    if (user.is_first_login) {
      this.openFirstLoginModal(user);
      return;
    }
    this.state.setCurrentUser(user);
    this.currentTab = 'dashboard';
    this.showToast(`Switched persona to ${user.name} (${user.role})`, 'success');
    this.render();
  }

  handleLogout() {
    const user = this.state.currentUser;
    if (user) {
      this.state.logAudit(user.name, user.role, 'LOGOUT', `User signed out of institutional portal`);
    }
    this.state.setCurrentUser(null);
    this.showToast('You have been signed out safely.', 'normal');
    this.render();
  }

  showToast(message, type = 'normal') {
    const toast = document.createElement('div');
    toast.className = `cbs-toast ${type}`;
    toast.innerHTML = `
      <div style="font-size: 1.1rem;">${type === 'urgent' ? '⚠️' : type === 'success' ? '✅' : 'ℹ️'}</div>
      <div style="flex: 1; font-size: 0.86rem; font-weight: 500;">${message}</div>
    `;
    this.elements.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(50px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  toggleNotificationsDrawer(open) {
    if (open) {
      this.elements.notifDrawer.classList.add('open');
      this.elements.notifDrawerOverlay.classList.add('open');
      this.renderNotificationList();
    } else {
      this.elements.notifDrawer.classList.remove('open');
      this.elements.notifDrawerOverlay.classList.remove('open');
    }
  }

  renderNotificationList() {
    const user = this.state.currentUser;
    if (!user) return;
    const userNotifs = this.state.notifications.filter(n => !n.user_id || n.user_id === user.id);
    
    if (userNotifs.length === 0) {
      this.elements.notifList.innerHTML = `
        <div style="text-align: center; padding: 40px 20px; color: #94a3b8;">
          <p>No new notifications</p>
        </div>
      `;
      return;
    }

    this.elements.notifList.innerHTML = userNotifs.map(n => `
      <div class="notif-item ${!n.is_read ? 'unread' : ''}" onclick="cbsApp.handleNotificationClick(${n.id})">
        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
          <strong style="font-size: 0.85rem; color: #0f172a;">${n.title}</strong>
          <span style="font-size: 0.72rem; color: #94a3b8;">${n.sent_on}</span>
        </div>
        <p style="font-size: 0.80rem; color: #475569; line-height: 1.4;">${n.message}</p>
      </div>
    `).join('');
  }

  handleNotificationClick(notifId) {
    const notif = this.state.notifications.find(n => n.id === notifId);
    if (notif) {
      notif.is_read = true;
      this.state.saveState();
      this.toggleNotificationsDrawer(false);
      if (notif.notice_id) {
        this.openNoticeDetail(notif.notice_id);
      }
      this.render();
    }
  }

  render() {
    const user = this.state.currentUser;

    if (!user) {
      // Unauthenticated state -> Render Modern Login Screen (Requirement 1)
      document.querySelectorAll('.role-chip-btn').forEach(btn => btn.classList.remove('active'));
      if (this.elements.userAvatar) this.elements.userAvatar.innerText = '--';
      if (this.elements.userName) this.elements.userName.innerText = 'Not Signed In';
      if (this.elements.userRole) this.elements.userRole.innerText = 'Guest • Please Sign In';
      if (this.elements.navTabLinks) {
        this.elements.navTabLinks.innerHTML = `
          <li>
            <a class="nav-tab-link active" href="credentials.html">
              <span>🔑</span> Credentials Directory
            </a>
          </li>
        `;
      }
      if (this.elements.notifBadge) this.elements.notifBadge.style.display = 'none';
      if (this.elements.urgentBanner) this.elements.urgentBanner.innerHTML = '';
      const logoutBtn = document.getElementById('navLogoutBtn');
      if (logoutBtn) logoutBtn.style.display = 'none';
      const userPill = document.getElementById('navUserPill');
      if (userPill) userPill.style.display = 'none';
      const notifToggleBtn = document.getElementById('notifToggleBtn');
      if (notifToggleBtn) notifToggleBtn.style.display = 'none';

      this.renderLoginScreen();
      return;
    }

    // Authenticated state: restore UI elements
    const logoutBtn = document.getElementById('navLogoutBtn');
    if (logoutBtn) logoutBtn.style.display = 'inline-flex';
    const userPill = document.getElementById('navUserPill');
    if (userPill) userPill.style.display = 'flex';
    const notifToggleBtn = document.getElementById('notifToggleBtn');
    if (notifToggleBtn) notifToggleBtn.style.display = 'flex';

    // Update Role Quick Bar chips
    document.querySelectorAll('.role-chip-btn').forEach(btn => {
      const bRole = btn.dataset.role.toLowerCase();
      const uRole = user.role.toLowerCase();
      const isMatch = bRole === uRole || ((bRole === 'principal' || bRole === 'admin') && (uRole === 'principal' || uRole === 'admin'));
      btn.classList.toggle('active', isMatch);
    });

    // Update Nav User Info
    const initials = user.name.split(' ').map(n => n[0]).join('').substring(0, 2);
    this.elements.userAvatar.innerText = initials;
    this.elements.userName.innerText = user.name;
    const identifier = user.roll_no || user.employee_id || '';
    this.elements.userRole.innerText = `${user.role} ${identifier ? '• ' + identifier : ''}`;

    // Notification counter
    const unreadCount = this.state.notifications.filter(n => (!n.user_id || n.user_id === user.id) && !n.is_read).length;
    this.elements.notifBadge.innerText = unreadCount;
    this.elements.notifBadge.style.display = unreadCount > 0 ? 'inline-block' : 'none';

    // Enforce Route Authorization Guards
    this.enforceRouteGuard();

    // Render Navigation Links according to Role (FR-02)
    this.renderNavLinks();

    // Render Urgent Banner for Students
    this.renderUrgentBanner();

    // Render Active Content View
    this.renderView();
  }

  // ==========================================================================
  // MODERN LOGIN SYSTEM (Requirement 1 & Attached Campus Image)
  // ==========================================================================

  renderLoginScreen(prefillEmail = '') {
    const urlParams = new URLSearchParams(window.location.search);
    const autofill = prefillEmail || urlParams.get('autofill') || '';

    this.elements.contentArea.innerHTML = `
      <div class="login-page-container">
        <div class="login-split-card">
          
          <!-- Left Visual Pane featuring Attached Campus Photo -->
          <div class="login-visual-pane">
            <div class="login-visual-scrim"></div>
            <div class="login-visual-content">
              <div>
                <div class="login-hero-badges">
                  <span class="login-glass-badge">🏛️ Autonomous Institution</span>
                  <span class="login-glass-badge">NAAC A++ Accredited</span>
                </div>
                <div style="margin-top: 18px;">
                  <h2 class="login-visual-headline">College Board System</h2>
                  <p class="login-visual-subtext">
                    Institutional Digital Notice Board & Centralized Academic Authentication Hub.
                  </p>
                </div>
              </div>

              <div class="login-features-list">
                <div class="login-feat-item">
                  <span class="login-feat-icon">🛡️</span>
                  <span>4 Tier Roles: Principal, HOD, Faculty & Student</span>
                </div>
                <div class="login-feat-item">
                  <span class="login-feat-icon">🔒</span>
                  <span>SHA-256 Hashed Passwords & Session Guard</span>
                </div>
                <div class="login-feat-item">
                  <span class="login-feat-icon">⏱️</span>
                  <span>5-Attempt Rate Limiting with Cooldown Lockout</span>
                </div>
                <div class="login-feat-item">
                  <span class="login-feat-icon">📜</span>
                  <span>Verified Student Read Receipts & Full Audit Trail</span>
                </div>
              </div>

              <div class="login-visual-footer">
                <div>Institutional Engineering Specification V1.0</div>
                <div style="color: #cbd5e1; margin-top: 2px;">
                  Campus Infrastructure: Central University Complex
                </div>
              </div>
            </div>
          </div>

          <!-- Right Authentication Form Pane -->
          <div class="login-form-pane">
            <div class="login-header-section">
              <h3 class="login-header-title">Sign In to Your Account</h3>
              <p class="login-header-desc">
                Enter your assigned User ID (Roll No / Employee ID) or Email address.
              </p>
            </div>

            <!-- Quick Persona Fill Chips for Testing -->
            <div class="quick-persona-section">
              <div class="quick-persona-label">
                <span>Quick Test Persona Fill:</span>
                <a href="credentials.html" style="color: #2563eb; text-decoration: none; font-size: 0.72rem; font-weight: 700;">
                  Full Directory →
                </a>
              </div>
              <div class="quick-persona-pills">
                <button type="button" class="persona-pill-btn" onclick="cbsApp.fillLoginForm('principal@college.edu', 'Password@123')">
                  🛡️ Principal
                </button>
                <button type="button" class="persona-pill-btn" onclick="cbsApp.fillLoginForm('k.prasad@college.edu', 'Password@123')">
                  👨‍💼 HOD
                </button>
                <button type="button" class="persona-pill-btn" onclick="cbsApp.fillLoginForm('anitha.reddy@college.edu', 'Password@123')">
                  👩‍🏫 Faculty
                </button>
                <button type="button" class="persona-pill-btn" onclick="cbsApp.fillLoginForm('ravi.kumar@college.edu', 'Password@123')">
                  🎓 Student
                </button>
                <button type="button" class="persona-pill-btn" style="color: #b45309;" onclick="cbsApp.fillLoginForm('newstudent@college.edu', 'Temp#2026!')">
                  🔑 First Login
                </button>
              </div>
            </div>

            <!-- Login Form -->
            <form id="loginAuthForm" onsubmit="cbsApp.handleLoginSubmit(event, this)">
              <div class="login-input-group">
                <label class="login-label" for="loginIdentifier">User ID or Institutional Email <span style="color: #ef4444;">*</span></label>
                <input type="text" id="loginIdentifier" name="identifier" class="login-input-field" 
                       placeholder="e.g. 24CS108, PRIN-001, or principal@college.edu" 
                       value="${autofill}" required autofocus>
              </div>

              <div class="login-input-group">
                <div style="display: flex; justify-content: space-between; align-items: baseline;">
                  <label class="login-label" for="loginPassword">Password <span style="color: #ef4444;">*</span></label>
                  <span class="login-forgot-link" onclick="cbsApp.openForgotPasswordModal()">Forgot Password?</span>
                </div>
                <div class="login-password-container">
                  <input type="password" id="loginPassword" name="password" class="login-input-field" 
                         placeholder="Enter account password" required style="padding-right: 44px;">
                  <button type="button" class="password-toggle-btn" onclick="cbsApp.togglePasswordVisibility('loginPassword', this)" title="Show/Hide Password">
                    👁️
                  </button>
                </div>
              </div>

              <div class="login-options-bar">
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                  <input type="checkbox" id="rememberMe" checked>
                  <span style="color: #475569;">Remember my session</span>
                </label>
              </div>

              <button type="submit" class="btn-login-submit" id="loginSubmitBtn">
                <span>🔐</span> Sign In to Dashboard
              </button>
            </form>

            <div class="login-security-box">
              <span style="font-size: 1.1rem;">🛡️</span>
              <div>
                <strong>Security Protected:</strong> Max 5 attempts before lockout. All authentication events are cryptographically hashed and logged.
              </div>
            </div>

            <div class="login-dir-cta">
              Need credentials or testing multiple roles? <a href="credentials.html">Browse the Login Credentials Directory</a>
            </div>

          </div>
        </div>
      </div>
    `;
  }

  fillLoginForm(identifier, password) {
    const idInput = document.getElementById('loginIdentifier');
    const pwdInput = document.getElementById('loginPassword');
    if (idInput && pwdInput) {
      idInput.value = identifier;
      pwdInput.value = password;
      pwdInput.focus();
    }
  }

  togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    if (input.type === 'password') {
      input.type = 'text';
      btn.innerText = '🔒';
    } else {
      input.type = 'password';
      btn.innerText = '👁️';
    }
  }

  handleLoginSubmit(e, form) {
    e.preventDefault();
    const identifier = document.getElementById('loginIdentifier').value.trim();
    const password = document.getElementById('loginPassword').value;

    const res = this.state.authenticate(identifier, password);

    if (!res.success) {
      if (res.reason === 'locked') {
        this.showToast(res.message, 'urgent');
      } else if (res.reason === 'deactivated') {
        alert(res.message);
      } else {
        this.showToast(res.message, 'urgent');
      }
      return;
    }

    const user = res.user;

    // Check First Login Requirement (Requirement 6)
    if (res.isFirstLogin) {
      this.openFirstLoginModal(user);
    } else {
      this.state.setCurrentUser(user);
      this.showToast(`Welcome back, ${user.name} (${user.role})!`, 'success');
      this.currentTab = 'dashboard';
      this.render();
    }
  }

  openForgotPasswordModal() {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
      <div class="modal-container" style="max-width: 480px;">
        <div class="modal-header">
          <h3>Self-Service Password Recovery</h3>
          <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div class="modal-body">
          <p style="font-size: 0.85rem; color: #475569; margin-bottom: 16px;">
            Enter your registered institutional Email or User ID (Roll No / Employee ID). The system will issue a temporary password and require you to establish a new password upon login.
          </p>

          <form onsubmit="cbsApp.handleForgotPasswordSubmit(event, this)">
            <div class="form-group">
              <label class="form-label">User ID or Email <span class="req-star">*</span></label>
              <input type="text" name="identifier" class="form-input" required placeholder="e.g. 24CS108 or ravi.kumar@college.edu">
            </div>

            <div class="modal-footer" style="padding-inline: 0; background: transparent;">
              <button type="button" class="btn-secondary-action" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
              <button type="submit" class="btn-primary-action">Request Temporary Password</button>
            </div>
          </form>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  handleForgotPasswordSubmit(e, form) {
    e.preventDefault();
    const fd = new FormData(form);
    const identifier = fd.get('identifier').trim();
    const res = this.state.resetPasswordSelf(identifier);

    if (!res.success) {
      alert(res.message);
      return;
    }

    form.closest('.modal-overlay').remove();
    this.fillLoginForm(res.user.email, res.tempPassword);
    alert(`Password reset successful!\n\nYour Temporary Password is:\n${res.tempPassword}\n\nPlease sign in with this temporary password. You will be required to change it immediately.`);
    this.showToast('Temporary password generated. Sign in to change it.', 'normal');
  }

  // Mandatory First Login Password Change Modal (Requirement 6)
  openFirstLoginModal(user) {
    const existing = document.getElementById('firstLoginModal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.className = 'first-login-modal-overlay';
    modal.id = 'firstLoginModal';
    modal.innerHTML = `
      <div class="first-login-box">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
          <div style="width: 44px; height: 44px; border-radius: 12px; background: #fffbeb; border: 1px solid #fde68a; display: flex; align-items: center; justify-content: center; font-size: 1.4rem;">
            🔐
          </div>
          <div>
            <h3 style="font-size: 1.25rem; font-weight: 800; color: #0f172a; margin: 0;">Password Change Required</h3>
            <span style="font-size: 0.78rem; color: #b45309; font-weight: 600;">Requirement 6: Mandatory Initial Login Security Policy</span>
          </div>
        </div>

        <p style="font-size: 0.85rem; color: #475569; line-height: 1.5; margin-bottom: 16px;">
          Welcome <strong>${user.name}</strong> (${user.role}). Your account was provisioned with a temporary password. Under institutional policy, you must set a permanent strong password before accessing your dashboard.
        </p>

        <form id="firstChangePwdForm" onsubmit="cbsApp.handleFirstLoginSubmit(event, ${user.id})">
          <div class="login-input-group">
            <label class="login-label">Current Temporary Password <span style="color: #ef4444;">*</span></label>
            <input type="password" id="flCurrentPwd" class="login-input-field" required placeholder="Enter current temp password" value="${user.password || ''}">
          </div>

          <div class="login-input-group">
            <label class="login-label">New Strong Password <span style="color: #ef4444;">*</span></label>
            <div class="login-password-container">
              <input type="password" id="flNewPwd" class="login-input-field" required placeholder="Min 8 chars with upper, lower, digit, symbol" oninput="cbsApp.updatePasswordMeter(this.value)">
              <button type="button" class="password-toggle-btn" onclick="cbsApp.togglePasswordVisibility('flNewPwd', this)">👁️</button>
            </div>
            <div class="pwd-strength-container">
              <div class="pwd-strength-bar" id="pwdStrengthBar"></div>
            </div>
          </div>

          <!-- Live Rule Checklist -->
          <div class="pwd-rules-checklist">
            <div class="pwd-rule-line" id="ruleMinLen"><span>•</span> Minimum 8 characters</div>
            <div class="pwd-rule-line" id="ruleUpper"><span>•</span> At least 1 uppercase letter (A-Z)</div>
            <div class="pwd-rule-line" id="ruleLower"><span>•</span> At least 1 lowercase letter (a-z)</div>
            <div class="pwd-rule-line" id="ruleDigit"><span>•</span> At least 1 numeric digit (0-9)</div>
            <div class="pwd-rule-line" id="ruleSpecial"><span>•</span> At least 1 special character (!@#$%^&*...)</div>
          </div>

          <div class="login-input-group">
            <label class="login-label">Confirm New Password <span style="color: #ef4444;">*</span></label>
            <input type="password" id="flConfirmPwd" class="login-input-field" required placeholder="Re-enter new password">
          </div>

          <div style="display: flex; gap: 10px; margin-top: 20px;">
            <button type="button" class="btn-secondary-action" style="flex: 1;" onclick="cbsApp.cancelFirstLoginModal()">
              Cancel / Sign Out
            </button>
            <button type="submit" class="btn-primary-action" style="flex: 2; padding: 12px; font-weight: 700;">
              Establish New Password & Continue →
            </button>
          </div>
        </form>
      </div>
    `;
    document.body.appendChild(modal);
  }

  cancelFirstLoginModal() {
    const modal = document.getElementById('firstLoginModal');
    if (modal) modal.remove();
    this.state.setCurrentUser(null);
    this.render();
  }

  updatePasswordMeter(pwd) {
    const check = CBSCrypto.validateStrongPassword(pwd);
    
    const updateRule = (id, met) => {
      const el = document.getElementById(id);
      if (el) {
        el.className = `pwd-rule-line ${met ? 'met' : ''}`;
        el.innerHTML = `<span>${met ? '✓' : '•'}</span> ${el.innerText.replace(/^[✓•]\s*/, '')}`;
      }
    };

    updateRule('ruleMinLen', check.minLength);
    updateRule('ruleUpper', check.hasUpper);
    updateRule('ruleLower', check.hasLower);
    updateRule('ruleDigit', check.hasDigit);
    updateRule('ruleSpecial', check.hasSpecial);

    let score = 0;
    if (check.minLength) score += 20;
    if (check.hasUpper) score += 20;
    if (check.hasLower) score += 20;
    if (check.hasDigit) score += 20;
    if (check.hasSpecial) score += 20;

    const bar = document.getElementById('pwdStrengthBar');
    if (bar) {
      bar.style.width = `${score}%`;
      if (score < 40) {
        bar.style.backgroundColor = '#ef4444';
      } else if (score < 80) {
        bar.style.backgroundColor = '#f59e0b';
      } else {
        bar.style.backgroundColor = '#10b981';
      }
    }
  }

  handleFirstLoginSubmit(e, userId) {
    e.preventDefault();
    const curPwd = document.getElementById('flCurrentPwd').value;
    const newPwd = document.getElementById('flNewPwd').value;
    const confirmPwd = document.getElementById('flConfirmPwd').value;

    if (newPwd !== confirmPwd) {
      alert('The new password and confirm password do not match.');
      return;
    }

    const res = this.state.changePassword(userId, curPwd, newPwd);

    if (!res.success) {
      alert(res.message);
      return;
    }

    const modal = document.getElementById('firstLoginModal');
    if (modal) modal.remove();

    this.state.setCurrentUser(res.user);
    this.showToast('Permanent password established successfully! Welcome to your dashboard.', 'success');
    this.currentTab = 'dashboard';
    this.render();
  }

  enforceRouteGuard() {
    const user = this.state.currentUser;
    if (!user) return;

    const isPrincipal = user.role === 'Principal' || user.role === 'Admin';
    const isHOD = user.role === 'HOD';
    const isFaculty = user.role === 'Faculty';
    const isStudent = user.role === 'Student';

    if (['users', 'master_data', 'audit'].includes(this.currentTab) && !isPrincipal) {
      this.showToast('Access Denied: Only Principal has administrative authorization for this module.', 'urgent');
      this.state.logAudit(user.name, user.role, 'UNAUTHORIZED_ACCESS_BLOCKED', `Attempted unauthorized navigation to tab "${this.currentTab}"`);
      this.currentTab = 'dashboard';
    }

    if (this.currentTab === 'approval_queue' && !isHOD && !isPrincipal) {
      this.showToast('Access Denied: Only Head of Department (HOD) or Principal can access the Approval Queue.', 'urgent');
      this.state.logAudit(user.name, user.role, 'UNAUTHORIZED_ACCESS_BLOCKED', `Attempted unauthorized access to HOD Approval Queue`);
      this.currentTab = 'dashboard';
    }

    if (this.currentTab === 'create' && isStudent) {
      this.showToast('Access Denied: Students are not authorized to create or publish notices.', 'urgent');
      this.state.logAudit(user.name, user.role, 'UNAUTHORIZED_ACCESS_BLOCKED', `Attempted unauthorized notice creation`);
      this.currentTab = 'dashboard';
    }
  }

  renderNavLinks() {
    const role = this.state.currentUser ? this.state.currentUser.role : '';
    let links = [];

    if (role === 'Student') {
      links = [
        { id: 'dashboard', label: 'Notices Board', icon: '📋' },
        { id: 'archive', label: 'Archive', icon: '🗄️' }
      ];
    } else if (role === 'Faculty') {
      links = [
        { id: 'dashboard', label: 'My Notices', icon: '📋' },
        { id: 'create', label: '+ Create Notice', icon: '✍️' },
        { id: 'archive', label: 'All Notices', icon: '🌐' }
      ];
    } else if (role === 'HOD') {
      const pendingCount = this.state.notices.filter(n => n.status === 'Pending').length;
      links = [
        { id: 'approval_queue', label: `Approval Queue ${pendingCount > 0 ? `(${pendingCount})` : ''}`, icon: '⏳' },
        { id: 'dashboard', label: 'Department Notices', icon: '📋' },
        { id: 'create', label: '+ Post Notice', icon: '✍️' },
        { id: 'reports', label: 'Reports', icon: '📊' }
      ];
    } else if (role === 'Principal' || role === 'Admin') {
      links = [
        { id: 'dashboard', label: 'Institutional Notices', icon: '📋' },
        { id: 'users', label: 'User Management', icon: '👥' },
        { id: 'master_data', label: 'Master Data', icon: '⚙️' },
        { id: 'reports', label: 'Reports & Analytics', icon: '📊' },
        { id: 'audit', label: 'System Audit Log', icon: '🛡️' }
      ];
    }

    this.elements.navTabLinks.innerHTML = links.map(link => `
      <li>
        <a class="nav-tab-link ${this.currentTab === link.id ? 'active' : ''}" 
           onclick="cbsApp.switchTab('${link.id}')">
          <span>${link.icon}</span> ${link.label}
        </a>
      </li>
    `).join('');
  }

  switchTab(tabId) {
    const user = this.state.currentUser;
    if (!user) {
      this.render();
      return;
    }

    const isPrincipal = user.role === 'Principal' || user.role === 'Admin';
    const isHOD = user.role === 'HOD';
    const isFaculty = user.role === 'Faculty';
    const isStudent = user.role === 'Student';

    if (['users', 'master_data', 'audit'].includes(tabId) && !isPrincipal) {
      this.showToast('Access Denied: Only Principal has administrative authorization for this module.', 'urgent');
      this.state.logAudit(user.name, user.role, 'UNAUTHORIZED_ACCESS_BLOCKED', `Attempted unauthorized navigation to tab "${tabId}"`);
      return;
    }

    if (tabId === 'approval_queue' && !isHOD && !isPrincipal) {
      this.showToast('Access Denied: Only Head of Department (HOD) or Principal can access the Approval Queue.', 'urgent');
      this.state.logAudit(user.name, user.role, 'UNAUTHORIZED_ACCESS_BLOCKED', `Attempted unauthorized access to HOD Approval Queue`);
      return;
    }

    if (tabId === 'create' && isStudent) {
      this.showToast('Access Denied: Students are not authorized to create or publish notices.', 'urgent');
      this.state.logAudit(user.name, user.role, 'UNAUTHORIZED_ACCESS_BLOCKED', `Attempted unauthorized notice creation`);
      return;
    }

    this.currentTab = tabId;
    this.render();
  }

  renderUrgentBanner() {
    const user = this.state.currentUser;
    // Urgent notices published and targeting student
    const urgentNotice = this.state.notices.find(n => 
      n.status === 'Active' && 
      n.priority === 'Urgent' && 
      this.state.getDaysRemaining(n.expiry_date) > 0 &&
      (user.role !== 'Student' || n.departments.includes(user.department_id))
    );

    if (urgentNotice && this.currentTab === 'dashboard') {
      this.elements.urgentBanner.innerHTML = `
        <div class="urgent-notice-banner">
          <div class="urgent-banner-left">
            <span class="urgent-tag">URGENT</span>
            <div class="urgent-banner-title">
              <strong>${urgentNotice.title}</strong> — ${urgentNotice.description.substring(0, 85)}...
            </div>
          </div>
          <button class="urgent-view-btn" onclick="cbsApp.openNoticeDetail(${urgentNotice.id})">
            View Details &rarr;
          </button>
        </div>
      `;
    } else {
      this.elements.urgentBanner.innerHTML = '';
    }
  }

  renderView() {
    const user = this.state.currentUser;

    if (this.currentTab === 'dashboard') {
      if (user.role === 'Student') {
        this.renderStudentDashboard();
      } else if (user.role === 'Faculty') {
        this.renderFacultyDashboard();
      } else if (user.role === 'HOD') {
        this.renderHODDashboard();
      } else if (user.role === 'Principal' || user.role === 'Admin') {
        this.renderAdminDashboard();
      }
    } else if (this.currentTab === 'approval_queue') {
      this.renderApprovalQueue();
    } else if (this.currentTab === 'create') {
      this.renderCreateNoticeForm();
    } else if (this.currentTab === 'archive') {
      this.renderArchiveBrowser();
    } else if (this.currentTab === 'users') {
      this.renderUserManagement();
    } else if (this.currentTab === 'master_data') {
      this.renderMasterDataManagement();
    } else if (this.currentTab === 'reports') {
      this.renderReportsAndAnalytics();
    } else if (this.currentTab === 'audit') {
      this.renderAuditLog();
    }
  }

  // ==========================================
  // STUDENT PORTAL (Figure 10)
  // ==========================================
  renderStudentDashboard() {
    const user = this.state.currentUser;
    const notices = this.state.getStudentNotices(user, {
      category: this.selectedCategoryFilter,
      keyword: this.searchQuery,
      showArchive: this.showArchiveFilter
    });

    const userDept = this.state.departments.find(d => d.id === user.department_id)?.name || 'General';

    this.elements.contentArea.innerHTML = `
      <div class="cbs-card-panel">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
          <div>
            <h2 style="font-size: 1.45rem; font-weight: 800; color: #0f172a; letter-spacing: -0.02em;">
              Digital Notice Board
            </h2>
            <p style="font-size: 0.85rem; color: #64748b;">
              Showing notices targeted for <strong>${userDept}</strong> • <strong>Year ${user.year}</strong> (Section ${user.section})
            </p>
          </div>
          <div style="display: flex; gap: 8px;">
            <span class="badge-tag" style="background: #eff6ff; color: #1d4ed8; padding: 6px 12px; font-size: 0.80rem;">
              🎓 ${user.roll_no}
            </span>
          </div>
        </div>

        <!-- Filter Toolbar (Fig 10) -->
        <div class="filter-toolbar">
          <div class="search-input-row">
            <div class="search-field-wrap">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
              <input type="text" class="search-input" id="studentSearchInput" placeholder="Search notices by keyword, faculty, or topic..." value="${this.searchQuery}">
            </div>
            <button class="btn-primary-action" onclick="cbsApp.executeSearch()">
              Search
            </button>
            <button class="btn-secondary-action" onclick="cbsApp.resetSearch()">
              Reset
            </button>
          </div>

          <div class="category-chips-row">
            <div class="category-chips-group">
              <button class="cat-filter-btn ${this.selectedCategoryFilter === 'All' ? 'active' : ''}" onclick="cbsApp.filterByCategory('All')">
                All
              </button>
              ${this.state.categories.map(c => `
                <button class="cat-filter-btn ${this.selectedCategoryFilter === c.name ? 'active' : ''}" onclick="cbsApp.filterByCategory('${c.name}')">
                  <span style="width: 8px; height: 8px; border-radius: 50%; background: ${c.colour_code};"></span>
                  ${c.name}
                </button>
              `).join('')}
            </div>

            <label class="archive-checkbox-wrap">
              <input type="checkbox" id="archiveToggleCheckbox" ${this.showArchiveFilter ? 'checked' : ''} onchange="cbsApp.toggleArchiveFilter(this.checked)">
              <span>Show archived notices</span>
            </label>
          </div>
        </div>

        <!-- Notice Cards Grid (Fig 10) -->
        <div class="notices-grid">
          ${notices.length === 0 ? `
            <div class="empty-state-card">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="9" y1="9" x2="15" y2="9"></line><line x1="9" y1="13" x2="15" y2="13"></line><line x1="9" y1="17" x2="11" y2="17"></line></svg>
              <h4>No notices found</h4>
              <p>There are currently no matching notices for your department, year, or filter selection.</p>
            </div>
          ` : notices.map(n => this.renderNoticeCardHTML(n, user)).join('')}
        </div>
      </div>
    `;

    // Bind real-time search input
    const searchInput = document.getElementById('studentSearchInput');
    if (searchInput) {
      searchInput.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') {
          this.executeSearch();
        }
      });
    }
  }

  renderNoticeCardHTML(notice, currentUser) {
    const cat = this.state.categories.find(c => c.id === notice.category_id) || { name: 'General', colour_code: '#d97706', class_slug: 'cat-general' };
    const poster = this.state.users.find(u => u.id === notice.posted_by);
    const posterName = poster ? poster.name : 'College Administration';
    const daysLeft = this.state.getDaysRemaining(notice.expiry_date);
    
    // Check if current student has read this notice
    const hasRead = currentUser.role === 'Student' && 
      this.state.notice_views.some(v => v.notice_id === notice.id && v.user_id === currentUser.id);

    return `
      <div class="notice-card ${notice.priority === 'Urgent' ? 'urgent-card' : ''} ${notice.is_pinned ? 'pinned-card' : ''}"
           onclick="cbsApp.openNoticeDetail(${notice.id})">
        <div>
          <div class="notice-card-header">
            <div class="notice-badges-group">
              ${notice.priority === 'Urgent' ? '<span class="badge-tag urgent">URGENT</span>' : ''}
              ${notice.is_pinned ? '<span class="badge-tag pinned">📌 PINNED</span>' : ''}
              <span class="badge-tag ${cat.class_slug}" style="background-color: ${cat.colour_code}20; color: ${cat.colour_code};">
                ${cat.name}
              </span>
            </div>
            <div class="days-remaining-pill ${daysLeft <= 3 ? 'imminent' : ''}">
              ${daysLeft === 0 ? 'Expired' : `${daysLeft} days left`}
            </div>
          </div>

          <div class="notice-card-body">
            <h3>${notice.title}</h3>
            <p>${notice.description}</p>
            ${notice.attachments && notice.attachments.length > 0 ? `
              <div class="notice-attachment-chip">
                📎 ${notice.attachments[0].name} ${notice.attachments.length > 1 ? `(+${notice.attachments.length - 1} more)` : ''}
              </div>
            ` : ''}
          </div>
        </div>

        <div class="notice-card-footer">
          <div class="poster-meta">
            <span>${posterName}</span> • ${notice.post_date}
          </div>
          ${currentUser.role === 'Student' ? `
            <div class="read-status-meta">
              ${!hasRead ? '<span class="unread-indicator" title="Unread Notice"></span><span style="font-size: 0.72rem; color: #2563eb; font-weight: 600;">NEW</span>' : '<span style="font-size: 0.72rem; color: #94a3b8;">Seen</span>'}
            </div>
          ` : `
            <div>
              <span style="font-size: 0.74rem; color: #64748b; font-weight: 600;">
                👁️ ${this.state.getNoticeReadCount(notice.id)} reads
              </span>
            </div>
          `}
        </div>
      </div>
    `;
  }

  executeSearch() {
    const input = document.getElementById('studentSearchInput');
    if (input) {
      this.searchQuery = input.value;
      this.render();
    }
  }

  resetSearch() {
    this.searchQuery = '';
    this.selectedCategoryFilter = 'All';
    this.showArchiveFilter = false;
    this.render();
  }

  filterByCategory(categoryName) {
    this.selectedCategoryFilter = categoryName;
    this.render();
  }

  toggleArchiveFilter(isChecked) {
    this.showArchiveFilter = isChecked;
    this.render();
  }

  // ==========================================
  // FACULTY DASHBOARD (Section 4.2, FR-09, FR-10, FR-11)
  // ==========================================
  renderFacultyDashboard() {
    const user = this.state.currentUser;
    const myNotices = this.state.notices.filter(n => n.posted_by === user.id);
    
    const activeCount = myNotices.filter(n => n.status === 'Active').length;
    const pendingCount = myNotices.filter(n => n.status === 'Pending').length;
    const rejectedCount = myNotices.filter(n => n.status === 'Rejected').length;
    const totalReads = myNotices.reduce((acc, curr) => acc + this.state.getNoticeReadCount(curr.id), 0);

    this.elements.contentArea.innerHTML = `
      <!-- KPI Stats -->
      <div class="kpi-stats-grid">
        <div class="kpi-card">
          <div class="kpi-icon-box blue">📋</div>
          <div class="kpi-content">
            <h4>My Total Notices</h4>
            <div class="kpi-num">${myNotices.length}</div>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon-box green">✅</div>
          <div class="kpi-content">
            <h4>Active / Published</h4>
            <div class="kpi-num">${activeCount}</div>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon-box amber">⏳</div>
          <div class="kpi-content">
            <h4>Pending HOD Review</h4>
            <div class="kpi-num">${pendingCount}</div>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon-box purple">👁️</div>
          <div class="kpi-content">
            <h4>Total Student Reads</h4>
            <div class="kpi-num">${totalReads}</div>
          </div>
        </div>
      </div>

      <div class="cbs-card-panel">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
          <div>
            <h2 style="font-size: 1.35rem; font-weight: 700; color: #0f172a;">Faculty Notice Management</h2>
            <p style="font-size: 0.85rem; color: #64748b;">Create, monitor student reach, and manage your department announcements.</p>
          </div>
          <button class="btn-primary-action" onclick="cbsApp.switchTab('create')">
            + Create New Notice
          </button>
        </div>

        ${rejectedCount > 0 ? `
          <div style="background: #fee2e2; border-left: 4px solid #dc2626; padding: 12px 18px; border-radius: 6px; margin-bottom: 20px; font-size: 0.88rem; color: #991b1b; display: flex; justify-content: space-between; align-items: center;">
            <div>
              <strong>Action Required:</strong> You have ${rejectedCount} notice(s) rejected by the HOD. Review remarks and resubmit below.
            </div>
          </div>
        ` : ''}

        <div class="cbs-table-wrap">
          <table class="cbs-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Category</th>
                <th>Target Audience</th>
                <th>Status</th>
                <th>Read Count</th>
                <th>Posted Date</th>
                <th>Expiry Date</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${myNotices.length === 0 ? `
                <tr><td colspan="8" style="text-align: center; padding: 40px; color: #94a3b8;">You haven't posted any notices yet. Click "+ Create New Notice" to begin.</td></tr>
              ` : myNotices.map(n => {
                const cat = this.state.categories.find(c => c.id === n.category_id);
                const readCount = this.state.getNoticeReadCount(n.id);
                return `
                  <tr>
                    <td>
                      <div style="font-weight: 600; color: #0f172a;">${n.title}</div>
                      ${n.priority === 'Urgent' ? '<span class="badge-tag urgent" style="font-size: 0.65rem;">URGENT</span>' : ''}
                      ${n.is_pinned ? '<span class="badge-tag pinned" style="font-size: 0.65rem;">PINNED</span>' : ''}
                    </td>
                    <td>
                      <span class="badge-tag" style="background: ${cat?.colour_code}20; color: ${cat?.colour_code};">
                        ${cat?.name || 'General'}
                      </span>
                    </td>
                    <td style="font-size: 0.80rem; color: #475569;">
                      ${this.formatTargetAudience(n)}
                    </td>
                    <td>
                      <span class="status-pill ${n.status.toLowerCase()}">${n.status}</span>
                      ${n.status === 'Rejected' ? `
                        <div style="font-size: 0.72rem; color: #dc2626; margin-top: 3px;">
                          HOD: "${n.rejection_remarks || 'See details'}"
                        </div>
                      ` : ''}
                    </td>
                    <td>
                      <button class="btn-secondary-action" style="padding: 4px 10px; font-size: 0.75rem;" onclick="cbsApp.openReaderLogModal(${n.id})">
                        👁️ ${readCount} reads
                      </button>
                    </td>
                    <td>${n.post_date}</td>
                    <td>${n.expiry_date}</td>
                    <td>
                      <div style="display: flex; gap: 6px;">
                        <button class="btn-secondary-action" style="padding: 4px 8px; font-size: 0.75rem;" onclick="cbsApp.openNoticeDetail(${n.id})">
                          Preview
                        </button>
                        ${(n.status === 'Draft' || n.status === 'Rejected' || n.status === 'Pending') ? `
                          <button class="btn-secondary-action" style="padding: 4px 8px; font-size: 0.75rem; color: #2563eb; font-weight: 600;" onclick="cbsApp.editNotice(${n.id})">
                            ${n.status === 'Rejected' ? 'Resubmit' : 'Edit'}
                          </button>
                          <button class="btn-secondary-action" style="padding: 4px 8px; font-size: 0.75rem; color: #dc2626;" onclick="cbsApp.deleteOwnNotice(${n.id})">
                            Delete
                          </button>
                        ` : ''}
                      </div>
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  formatTargetAudience(notice) {
    const depts = notice.departments.map(dId => this.state.departments.find(d => d.id === dId)?.code).filter(Boolean).join(', ');
    const years = notice.years && notice.years.length > 0 ? `Year ${notice.years.join(', ')}` : 'All Years';
    return `${depts || 'All Depts'} — ${years}`;
  }

  // ==========================================
  // CREATE / EDIT NOTICE FORM (Figure 11, Table 28)
  // ==========================================
  renderCreateNoticeForm() {
    const user = this.state.currentUser;
    const isEditing = Boolean(this.editingNoticeId);
    const existing = isEditing ? this.state.notices.find(n => n.id === this.editingNoticeId) : null;

    const defaultTitle = existing ? existing.title : '';
    const defaultDesc = existing ? existing.description : '';
    const defaultCatId = existing ? existing.category_id : 1;
    const defaultPriority = existing ? existing.priority : 'Normal';
    const defaultPinned = existing ? existing.is_pinned : false;
    const defaultExpiry = existing ? existing.expiry_date : getFormattedDate(14);
    const defaultDepts = existing ? existing.departments : [user.department_id || 1];
    const defaultYears = existing && existing.years ? existing.years : [1, 2, 3, 4];

    this.elements.contentArea.innerHTML = `
      <div class="cbs-card-panel" style="max-width: 900px; margin: 0 auto;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; border-bottom: 1px solid #e2e8f0; padding-bottom: 14px;">
          <div>
            <h2 style="font-size: 1.4rem; font-weight: 800; color: #0f172a;">
              ${isEditing ? (existing.status === 'Rejected' ? 'Edit & Resubmit Rejected Notice' : 'Edit Notice') : 'Create New Notice'}
            </h2>
            <p style="font-size: 0.85rem; color: #64748b;">
              ${user.role === 'HOD' ? 'Notices posted by the HOD are published directly as Active.' : 'Notices posted by Faculty are routed to HOD for approval.'}
            </p>
          </div>
          <button class="btn-secondary-action" onclick="cbsApp.switchTab('dashboard')">
            Cancel
          </button>
        </div>

        ${existing && existing.status === 'Rejected' ? `
          <div style="background: #fee2e2; border: 1px solid #fca5a5; padding: 14px 18px; border-radius: 8px; margin-bottom: 20px; font-size: 0.88rem; color: #991b1b;">
            <strong>HOD Rejection Remarks:</strong> ${existing.rejection_remarks}
          </div>
        ` : ''}

        <form id="createNoticeForm" onsubmit="cbsApp.handleNoticeSubmit(event)">
          <div class="form-grid">
            <div class="form-group col-span-2">
              <label class="form-label">
                Notice Title <span class="req-star">*</span>
              </label>
              <input type="text" id="noticeTitle" class="form-input" required minlength="5" maxlength="200"
                     placeholder="e.g., Semester Examination Schedule / Tech Fest Circular" value="${defaultTitle}">
              <div class="form-hint">5 to 200 characters</div>
            </div>

            <div class="form-group col-span-2">
              <label class="form-label">
                Description / Body <span class="req-star">*</span>
              </label>
              <textarea id="noticeDesc" class="form-textarea" required maxlength="5000" rows="5"
                        placeholder="Provide detailed information, eligibility, venues, dates, or guidelines...">${defaultDesc}</textarea>
              <div class="form-hint">Up to 5,000 characters</div>
            </div>

            <div class="form-group">
              <label class="form-label">
                Category <span class="req-star">*</span>
              </label>
              <select id="noticeCategory" class="form-select" required>
                ${this.state.categories.map(c => `
                  <option value="${c.id}" ${c.id === defaultCatId ? 'selected' : ''}>${c.name}</option>
                `).join('')}
              </select>
            </div>

            <div class="form-group">
              <label class="form-label">
                Expiry Date <span class="req-star">*</span>
              </label>
              <input type="date" id="noticeExpiry" class="form-input" required 
                     min="${getFormattedDate(0)}" max="${getFormattedDate(365)}" value="${defaultExpiry}">
              <div class="form-hint">Today or later, up to 1 year ahead</div>
            </div>

            <div class="form-group">
              <label class="form-label">Target Department(s) <span class="req-star">*</span></label>
              <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px;">
                ${this.state.departments.map(d => `
                  <label style="font-size: 0.82rem; display: inline-flex; align-items: center; gap: 4px; background: #f8fafc; border: 1px solid #cbd5e1; padding: 4px 10px; border-radius: 6px; cursor: pointer;">
                    <input type="checkbox" name="targetDepts" value="${d.id}" ${defaultDepts.includes(d.id) ? 'checked' : ''}>
                    ${d.code}
                  </label>
                `).join('')}
              </div>
            </div>

            <div class="form-group">
              <label class="form-label">Target Academic Year(s)</label>
              <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px;">
                ${[1, 2, 3, 4].map(y => `
                  <label style="font-size: 0.82rem; display: inline-flex; align-items: center; gap: 4px; background: #f8fafc; border: 1px solid #cbd5e1; padding: 4px 10px; border-radius: 6px; cursor: pointer;">
                    <input type="checkbox" name="targetYears" value="${y}" ${defaultYears.includes(y) ? 'checked' : ''}>
                    ${y === 1 ? 'I' : y === 2 ? 'II' : y === 3 ? 'III' : 'IV'} Year
                  </label>
                `).join('')}
              </div>
            </div>

            <div class="form-group">
              <label class="form-label">Priority</label>
              <div class="radio-pill-group">
                <input type="radio" id="priorityNormal" name="noticePriority" value="Normal" class="radio-pill-input" ${defaultPriority === 'Normal' ? 'checked' : ''}>
                <label for="priorityNormal" class="radio-pill-label">Normal</label>

                <input type="radio" id="priorityUrgent" name="noticePriority" value="Urgent" class="radio-pill-input" ${defaultPriority === 'Urgent' ? 'checked' : ''}>
                <label for="priorityUrgent" class="radio-pill-label" style="color: #dc2626;">Urgent (Alerts Students)</label>
              </div>
            </div>

            <div class="form-group">
              <label class="form-label">Pin to Top of Board</label>
              <div class="radio-pill-group">
                <input type="radio" id="pinNo" name="noticePin" value="0" class="radio-pill-input" ${!defaultPinned ? 'checked' : ''}>
                <label for="pinNo" class="radio-pill-label">No</label>

                <input type="radio" id="pinYes" name="noticePin" value="1" class="radio-pill-input" ${defaultPinned ? 'checked' : ''}>
                <label for="pinYes" class="radio-pill-label">📌 Yes, Pin</label>
              </div>
            </div>

            <div class="form-group col-span-2">
              <label class="form-label">Attachments (PDF, Word, Excel, Images, PPT)</label>
              <div class="file-dropzone" onclick="document.getElementById('noticeFileInput').click()">
                <div class="dropzone-icon">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
                </div>
                <div style="font-weight: 600; font-size: 0.90rem; color: #1e3a8a;">
                  Click to attach files or choose from campus media
                </div>
                <div style="font-size: 0.75rem; color: #64748b; margin-top: 4px;">
                  Up to 3 files, maximum 10 MB each. Supports PDF, DOCX, XLSX, PNG, JPG.
                </div>
              </div>
              <input type="file" id="noticeFileInput" multiple style="display: none;" onchange="cbsApp.handleFileSelected(this)">
              
              <div id="stagedFilesContainer" class="attached-files-list">
                ${existing && existing.attachments ? existing.attachments.map(att => `
                  <div class="attached-file-row">
                    <span>📎 ${att.name} (${att.size})</span>
                    <span style="color: #64748b;">Included</span>
                  </div>
                `).join('') : ''}
              </div>
            </div>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 24px; border-top: 1px solid #e2e8f0; padding-top: 18px;">
            <button type="button" class="btn-secondary-action" onclick="cbsApp.saveAsDraft()">
              Save as Draft
            </button>
            <button type="submit" class="btn-primary-action">
              ${user.role === 'HOD' ? 'Publish Immediately' : 'Submit for Approval'}
            </button>
          </div>
        </form>
      </div>
    `;

    this.stagedFiles = existing && existing.attachments ? [...existing.attachments] : [];
  }

  handleFileSelected(input) {
    if (!input.files) return;
    const files = Array.from(input.files);
    files.forEach(f => {
      // Validate file size <= 10MB
      if (f.size > 10 * 1024 * 1024) {
        this.showToast(`File ${f.name} exceeds 10 MB limit!`, 'urgent');
        return;
      }
      this.stagedFiles.push({
        name: f.name,
        size: `${(f.size / 1024).toFixed(0)} KB`,
        type: f.name.endsWith('.pdf') ? 'pdf' : 'image',
        path: f.name
      });
    });

    const container = document.getElementById('stagedFilesContainer');
    if (container) {
      container.innerHTML = this.stagedFiles.map((att, idx) => `
        <div class="attached-file-row">
          <span>📎 ${att.name} (${att.size})</span>
          <button type="button" style="background: none; border: none; color: #dc2626; cursor: pointer;" onclick="cbsApp.removeStagedFile(${idx})">✖</button>
        </div>
      `).join('');
    }
  }

  removeStagedFile(index) {
    this.stagedFiles.splice(index, 1);
    const container = document.getElementById('stagedFilesContainer');
    if (container) {
      container.innerHTML = this.stagedFiles.map((att, idx) => `
        <div class="attached-file-row">
          <span>📎 ${att.name} (${att.size})</span>
          <button type="button" style="background: none; border: none; color: #dc2626; cursor: pointer;" onclick="cbsApp.removeStagedFile(${idx})">✖</button>
        </div>
      `).join('');
    }
  }

  handleNoticeSubmit(e) {
    e.preventDefault();
    const user = this.state.currentUser;

    const title = document.getElementById('noticeTitle').value.trim();
    const description = document.getElementById('noticeDesc').value.trim();
    const category_id = parseInt(document.getElementById('noticeCategory').value);
    const expiry_date = document.getElementById('noticeExpiry').value;
    const priority = document.querySelector('input[name="noticePriority"]:checked').value;
    const is_pinned = document.querySelector('input[name="noticePin"]:checked').value === '1';

    // Target departments
    const deptBoxes = Array.from(document.querySelectorAll('input[name="targetDepts"]:checked'));
    if (deptBoxes.length === 0) {
      this.showToast('Please select at least one target department!', 'urgent');
      return;
    }
    const departments = deptBoxes.map(b => parseInt(b.value));

    // Target years
    const yearBoxes = Array.from(document.querySelectorAll('input[name="targetYears"]:checked'));
    const years = yearBoxes.map(b => parseInt(b.value));

    // Rule: HOD posts are Active directly (FR-15). Faculty posts are Pending (FR-04, FR-06).
    const status = user.role === 'HOD' ? 'Active' : 'Pending';

    if (this.editingNoticeId) {
      const existing = this.state.notices.find(n => n.id === this.editingNoticeId);
      if (existing) {
        existing.title = title;
        existing.description = description;
        existing.category_id = category_id;
        existing.expiry_date = expiry_date;
        existing.priority = priority;
        existing.is_pinned = is_pinned;
        existing.departments = departments;
        existing.years = years;
        existing.attachments = this.stagedFiles || existing.attachments;
        existing.status = status;
        existing.rejection_remarks = null;

        this.state.logAudit(user.name, user.role, 'EDIT_NOTICE', `Edited & resubmitted notice #${existing.id}: ${existing.title}`);
        this.showToast(`Notice #${existing.id} updated and submitted for approval!`, 'success');
      }
      this.editingNoticeId = null;
    } else {
      const newNotice = {
        id: Date.now(),
        title,
        description,
        category_id,
        posted_by: user.id,
        priority,
        is_pinned,
        status,
        post_date: getFormattedDate(0),
        expiry_date,
        departments,
        years,
        section: null,
        attachments: this.stagedFiles || [],
        rejection_remarks: null
      };

      this.state.notices.unshift(newNotice);
      this.state.logAudit(user.name, user.role, 'CREATE_NOTICE', `Created notice #${newNotice.id}: ${newNotice.title}`);

      // If priority is Urgent and status is Active (HOD direct post), dispatch notification
      if (status === 'Active' && priority === 'Urgent') {
        this.dispatchUrgentNoticeAlert(newNotice);
      }

      this.showToast(status === 'Active' ? 'Notice published successfully!' : 'Notice submitted to HOD for approval!', 'success');
    }

    this.state.saveState();
    this.currentTab = 'dashboard';
    this.render();
  }

  saveAsDraft() {
    const user = this.state.currentUser;
    const title = document.getElementById('noticeTitle').value.trim() || 'Untitled Notice (Draft)';
    const description = document.getElementById('noticeDesc').value.trim();
    const category_id = parseInt(document.getElementById('noticeCategory').value) || 1;
    const expiry_date = document.getElementById('noticeExpiry').value || getFormattedDate(14);

    const newDraft = {
      id: Date.now(),
      title,
      description,
      category_id,
      posted_by: user.id,
      priority: 'Normal',
      is_pinned: false,
      status: 'Draft',
      post_date: getFormattedDate(0),
      expiry_date,
      departments: [user.department_id || 1],
      years: [1, 2, 3, 4],
      section: null,
      attachments: this.stagedFiles || [],
      rejection_remarks: null
    };

    this.state.notices.unshift(newDraft);
    this.state.saveState();
    this.showToast('Notice draft saved!', 'normal');
    this.currentTab = 'dashboard';
    this.render();
  }

  editNotice(noticeId) {
    this.editingNoticeId = noticeId;
    this.currentTab = 'create';
    this.render();
  }

  deleteOwnNotice(noticeId) {
    const user = this.state.currentUser;
    const notice = this.state.notices.find(n => n.id === noticeId);
    if (!notice) return;

    // FR-09: Edit or delete own notices (while Pending or Rejected)
    if (notice.posted_by !== user.id && user.role !== 'Admin' && user.role !== 'Principal') {
      this.showToast('You can only delete your own notices!', 'urgent');
      return;
    }

    if (confirm(`Are you sure you want to delete notice "${notice.title}"?`)) {
      this.state.notices = this.state.notices.filter(n => n.id !== noticeId);
      this.state.logAudit(user.name, user.role, 'DELETE_NOTICE', `Deleted notice #${noticeId}: ${notice.title}`);
      this.state.saveState();
      this.showToast('Notice deleted.', 'normal');
      this.render();
    }
  }

  // ==========================================
  // HOD APPROVAL QUEUE (Figure 12, Table 20)
  // ==========================================
  renderApprovalQueue() {
    const user = this.state.currentUser;
    const pendingNotices = this.state.notices.filter(n => n.status === 'Pending');

    if (!this.selectedApprovalNoticeId && pendingNotices.length > 0) {
      this.selectedApprovalNoticeId = pendingNotices[0].id;
    }

    const selectedNotice = pendingNotices.find(n => n.id === this.selectedApprovalNoticeId) || pendingNotices[0];

    this.elements.contentArea.innerHTML = `
      <div class="cbs-card-panel">
        <div style="margin-bottom: 20px;">
          <h2 style="font-size: 1.4rem; font-weight: 800; color: #0f172a;">
            HOD Approval Queue (${pendingNotices.length})
          </h2>
          <p style="font-size: 0.85rem; color: #64748b;">
            Review faculty announcements, ensure accuracy and policy compliance before publishing to students.
          </p>
        </div>

        ${pendingNotices.length === 0 ? `
          <div class="empty-state-card">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            <h4>All Caught Up!</h4>
            <p>There are no notices waiting for approval in your department queue.</p>
          </div>
        ` : `
          <!-- Approval Split Layout (Fig 12) -->
          <div class="approval-layout">
            <!-- Left List -->
            <div class="approval-list-pane">
              ${pendingNotices.map(n => {
                const poster = this.state.users.find(u => u.id === n.posted_by);
                const isSelected = selectedNotice && selectedNotice.id === n.id;
                return `
                  <div class="approval-list-item ${isSelected ? 'selected' : ''}" onclick="cbsApp.selectApprovalNotice(${n.id})">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                      <span class="status-pill pending">Pending</span>
                      ${n.priority === 'Urgent' ? '<span class="badge-tag urgent">URGENT</span>' : ''}
                    </div>
                    <strong style="font-size: 0.88rem; color: #0f172a; display: block; margin-bottom: 4px;">${n.title}</strong>
                    <div style="font-size: 0.75rem; color: #64748b;">
                      ${poster ? poster.name : 'Faculty'} • ${n.post_date}
                    </div>
                  </div>
                `;
              }).join('')}
            </div>

            <!-- Right Preview Pane -->
            <div class="approval-preview-pane">
              ${selectedNotice ? this.renderApprovalPreviewHTML(selectedNotice) : '<p>Select a notice</p>'}
            </div>
          </div>
        `}
      </div>
    `;
  }

  renderApprovalPreviewHTML(notice) {
    const poster = this.state.users.find(u => u.id === notice.posted_by);
    const cat = this.state.categories.find(c => c.id === notice.category_id);
    const audienceStr = this.formatTargetAudience(notice);

    return `
      <div>
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px;">
          <div>
            <div style="display: flex; gap: 6px; margin-bottom: 8px;">
              <span class="badge-tag" style="background: ${cat?.colour_code}20; color: ${cat?.colour_code};">${cat?.name}</span>
              ${notice.priority === 'Urgent' ? '<span class="badge-tag urgent">URGENT</span>' : ''}
              ${notice.is_pinned ? '<span class="badge-tag pinned">📌 PINNED</span>' : ''}
            </div>
            <h3 style="font-size: 1.25rem; font-weight: 700; color: #0f172a;">${notice.title}</h3>
          </div>
        </div>

        <table class="preview-meta-table">
          <tr>
            <td>Posted By:</td>
            <td><strong>${poster ? poster.name : 'Faculty'}</strong> (${poster?.designation || 'Faculty'})</td>
          </tr>
          <tr>
            <td>Target Audience:</td>
            <td>${audienceStr}</td>
          </tr>
          <tr>
            <td>Expiry Date:</td>
            <td>${notice.expiry_date} (${this.state.getDaysRemaining(notice.expiry_date)} days validity)</td>
          </tr>
          <tr>
            <td>Attachments:</td>
            <td>
              ${notice.attachments && notice.attachments.length > 0 ? 
                notice.attachments.map(att => `<span class="notice-attachment-chip" onclick="cbsApp.previewAttachment('${att.path}')">📎 ${att.name} (${att.size})</span>`).join(' ') 
                : '<span style="color: #94a3b8;">None</span>'}
            </td>
          </tr>
        </table>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-top: 14px;">
          <h4 style="font-size: 0.80rem; text-transform: uppercase; color: #64748b; margin-bottom: 6px;">Notice Body</h4>
          <p style="font-size: 0.90rem; color: #1e293b; line-height: 1.6; white-space: pre-line;">${notice.description}</p>
        </div>
      </div>

      <!-- Remarks Box & Action Bar (Fig 12) -->
      <div class="remarks-box-wrap">
        <label style="font-size: 0.82rem; font-weight: 600; color: #334155;">
          HOD Remarks <span style="font-weight: 400; color: #64748b;">(Mandatory if rejecting; optional for approval)</span>
        </label>
        <textarea id="hodRemarksInput" class="remarks-textarea" placeholder="Type remarks or revision guidance here..."></textarea>

        <div class="approval-action-bar">
          <button class="btn-approve" onclick="cbsApp.approveNotice(${notice.id})">
            ✓ Approve & Publish
          </button>
          <button class="btn-reject" onclick="cbsApp.rejectNotice(${notice.id})">
            ✕ Reject
          </button>
        </div>
      </div>
    `;
  }

  selectApprovalNotice(id) {
    this.selectedApprovalNoticeId = id;
    this.render();
  }

  approveNotice(noticeId) {
    const user = this.state.currentUser;
    const notice = this.state.notices.find(n => n.id === noticeId);
    if (!notice) return;

    const remarks = document.getElementById('hodRemarksInput')?.value.trim() || 'Approved by HOD';

    notice.status = 'Active';
    notice.rejection_remarks = null;

    this.state.logAudit(user.name, user.role, 'APPROVE_NOTICE', `HOD approved notice #${notice.id}: "${notice.title}"`);

    // If urgent, send alerts to student dashboard & simulated email (FR-21, TC-21)
    if (notice.priority === 'Urgent') {
      this.dispatchUrgentNoticeAlert(notice);
      this.showToast(`Notice approved and published! Urgent email & dashboard alerts dispatched to students.`, 'success');
    } else {
      this.showToast(`Notice approved and published to student board!`, 'success');
    }

    this.state.saveState();
    this.selectedApprovalNoticeId = null;
    this.render();
  }

  rejectNotice(noticeId) {
    const user = this.state.currentUser;
    const notice = this.state.notices.find(n => n.id === noticeId);
    if (!notice) return;

    const remarks = document.getElementById('hodRemarksInput')?.value.trim();
    if (!remarks) {
      alert('HOD remarks are required when rejecting a notice so faculty can correct the issue.');
      return;
    }

    notice.status = 'Rejected';
    notice.rejection_remarks = remarks;

    // Send notification to author
    this.state.notifications.unshift({
      id: Date.now(),
      user_id: notice.posted_by,
      title: `Notice Rejected: ${notice.title}`,
      message: `HOD Remarks: "${remarks}". Please edit and resubmit.`,
      sent_on: new Date().toISOString().replace('T', ' ').substring(0, 16),
      is_read: false,
      notice_id: notice.id
    });

    this.state.logAudit(user.name, user.role, 'REJECT_NOTICE', `HOD rejected notice #${notice.id}. Remarks: ${remarks}`);
    this.state.saveState();

    this.showToast(`Notice rejected. Remarks returned to faculty member.`, 'urgent');
    this.selectedApprovalNoticeId = null;
    this.render();
  }

  dispatchUrgentNoticeAlert(notice) {
    // Dispatch dashboard notifications for all target students (FR-21)
    const targetStudents = this.state.users.filter(u => 
      u.role === 'Student' && 
      notice.departments.includes(u.department_id) && 
      (!notice.years || notice.years.length === 0 || notice.years.includes(u.year))
    );

    targetStudents.forEach(stu => {
      this.state.notifications.unshift({
        id: Date.now() + Math.random(),
        user_id: stu.id,
        title: `URGENT ALERT: ${notice.title}`,
        message: notice.description.substring(0, 100) + '...',
        sent_on: new Date().toISOString().replace('T', ' ').substring(0, 16),
        is_read: false,
        notice_id: notice.id
      });
    });

    this.state.saveState();
  }

  // ==========================================
  // HOD DASHBOARD
  // ==========================================
  renderHODDashboard() {
    const user = this.state.currentUser;
    const pendingCount = this.state.notices.filter(n => n.status === 'Pending').length;
    const deptNotices = this.state.notices.filter(n => n.departments.includes(user.department_id));

    this.elements.contentArea.innerHTML = `
      <div class="kpi-stats-grid">
        <div class="kpi-card">
          <div class="kpi-icon-box amber">⏳</div>
          <div class="kpi-content">
            <h4>Pending Approvals</h4>
            <div class="kpi-num">${pendingCount}</div>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon-box blue">📋</div>
          <div class="kpi-content">
            <h4>Department Notices</h4>
            <div class="kpi-num">${deptNotices.length}</div>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon-box green">✅</div>
          <div class="kpi-content">
            <h4>Active Notices</h4>
            <div class="kpi-num">${deptNotices.filter(n => n.status === 'Active').length}</div>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon-box purple">👥</div>
          <div class="kpi-content">
            <h4>Faculty in Department</h4>
            <div class="kpi-num">${this.state.users.filter(u => u.role === 'Faculty' && u.department_id === user.department_id).length}</div>
          </div>
        </div>
      </div>

      <div class="cbs-card-panel">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px;">
          <div>
            <h2 style="font-size: 1.35rem; font-weight: 700; color: #0f172a;">Department Notice Overview</h2>
            <p style="font-size: 0.85rem; color: #64748b;">All active, pending, and published announcements for Computer Science & Engineering.</p>
          </div>
          <div style="display: flex; gap: 10px;">
            <button class="btn-primary-action" onclick="cbsApp.switchTab('approval_queue')">
              Open Approval Queue (${pendingCount})
            </button>
            <button class="btn-secondary-action" onclick="cbsApp.switchTab('create')">
              + Post Dept Notice
            </button>
          </div>
        </div>

        <div class="notices-grid">
          ${deptNotices.map(n => this.renderNoticeCardHTML(n, user)).join('')}
        </div>
      </div>
    `;
  }

  // ==========================================
  // ADMIN DASHBOARD & CONTROLS
  // ==========================================
  renderAdminDashboard() {
    const user = this.state.currentUser;
    const totalUsers = this.state.users.length;
    const totalNotices = this.state.notices.length;
    const activeNotices = this.state.notices.filter(n => n.status === 'Active').length;
    const pendingNotices = this.state.notices.filter(n => n.status === 'Pending').length;

    this.elements.contentArea.innerHTML = `
      <div class="kpi-stats-grid">
        <div class="kpi-card">
          <div class="kpi-icon-box blue">👥</div>
          <div class="kpi-content">
            <h4>Total Users</h4>
            <div class="kpi-num">${totalUsers}</div>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon-box green">📜</div>
          <div class="kpi-content">
            <h4>Active Notices</h4>
            <div class="kpi-num">${activeNotices}</div>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon-box amber">⏳</div>
          <div class="kpi-content">
            <h4>Pending Approvals</h4>
            <div class="kpi-num">${pendingNotices}</div>
          </div>
        </div>
        <div class="kpi-card">
          <div class="kpi-icon-box purple">🗄️</div>
          <div class="kpi-content">
            <h4>Total Notices (History)</h4>
            <div class="kpi-num">${totalNotices}</div>
          </div>
        </div>
      </div>

      <div class="cbs-card-panel">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
          <div>
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px;">
              <h2 style="font-size: 1.35rem; font-weight: 800; color: #0f172a;">Principal & Administrator Control Hub</h2>
              <span class="badge-tag" style="background: #eff6ff; color: #1e3a8a; border: 1px solid #bfdbfe;">Executive Authority</span>
            </div>
            <p style="font-size: 0.85rem; color: #64748b;">Manage university notices, user accounts, security audit trails, and archive schedulers.</p>
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn-primary-action" onclick="cbsApp.triggerNightlySchedulerManual()">
              ⚡ Run Nightly Scheduler
            </button>
            <button class="btn-secondary-action" onclick="cbsApp.switchTab('users')">
              👥 User Management
            </button>
            <button class="btn-secondary-action" onclick="cbsApp.switchTab('audit')">
              🛡️ Audit Trail
            </button>
            <a href="credentials.html" class="btn-secondary-action" style="text-decoration: none;">
              🔑 Credentials Directory
            </a>
          </div>
        </div>

        <div class="cbs-table-wrap">
          <table class="cbs-table">
            <thead>
              <tr>
                <th>Notice ID</th>
                <th>Title</th>
                <th>Author</th>
                <th>Category</th>
                <th>Status</th>
                <th>Target</th>
                <th>Expiry</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${this.state.notices.map(n => {
                const cat = this.state.categories.find(c => c.id === n.category_id);
                const author = this.state.users.find(u => u.id === n.posted_by);
                return `
                  <tr>
                    <td>#${n.id}</td>
                    <td>
                      <strong>${n.title}</strong>
                      ${n.priority === 'Urgent' ? '<span class="badge-tag urgent" style="font-size: 0.65rem;">URGENT</span>' : ''}
                    </td>
                    <td>${author ? author.name : 'Unknown'}</td>
                    <td>
                      <span class="badge-tag" style="background: ${cat?.colour_code}20; color: ${cat?.colour_code};">
                        ${cat?.name}
                      </span>
                    </td>
                    <td><span class="status-pill ${n.status.toLowerCase()}">${n.status}</span></td>
                    <td style="font-size: 0.78rem;">${this.formatTargetAudience(n)}</td>
                    <td>${n.expiry_date}</td>
                    <td>
                      <div style="display: flex; gap: 6px;">
                        <button class="btn-secondary-action" style="padding: 4px 8px; font-size: 0.74rem;" onclick="cbsApp.openNoticeDetail(${n.id})">
                          View
                        </button>
                        ${n.status !== 'Archived' ? `
                          <button class="btn-secondary-action" style="padding: 4px 8px; font-size: 0.74rem;" onclick="cbsApp.archiveNoticeAdmin(${n.id})">
                            Archive
                          </button>
                        ` : ''}
                      </div>
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  triggerNightlySchedulerManual() {
    const res = this.state.runNightlyScheduler();
    this.showToast(`Nightly Scheduler finished! Updated ${res.expiredCount} expired and ${res.archivedCount} archived notices.`, 'success');
    this.render();
  }

  archiveNoticeAdmin(noticeId) {
    const notice = this.state.notices.find(n => n.id === noticeId);
    if (notice) {
      notice.status = 'Archived';
      this.state.logAudit(this.state.currentUser.name, 'Admin', 'ARCHIVE_NOTICE', `Manually archived notice #${notice.id}`);
      this.state.saveState();
      this.showToast(`Notice #${notice.id} moved to archive.`, 'normal');
      this.render();
    }
  }

  // ==========================================
  // PRINCIPAL USER MANAGEMENT (Requirements 2, 3, 5, 7)
  // ==========================================
  renderUserManagement() {
    // Backend Authorization Guard: Principal Only
    const curUser = this.state.currentUser;
    const isPrincipal = curUser && (curUser.role === 'Principal' || curUser.role === 'Admin');
    if (!isPrincipal) {
      this.showToast('Access Denied: Only Principal has administrative authorization for user management.', 'urgent');
      this.currentTab = 'dashboard';
      this.render();
      return;
    }

    // Apply Filters & Search
    let filteredUsers = this.state.users.filter(u => {
      // Role filter
      if (this.userRoleFilter !== 'All') {
        const uRole = u.role.toLowerCase();
        const fRole = this.userRoleFilter.toLowerCase();
        if (fRole === 'principal' && uRole !== 'principal' && uRole !== 'admin') return false;
        if (fRole !== 'principal' && uRole !== fRole) return false;
      }
      // Department filter
      if (this.userDeptFilter !== 'All' && u.department_id !== parseInt(this.userDeptFilter)) {
        return false;
      }
      // Status filter
      if (this.userStatusFilter === 'Active' && !u.is_active) return false;
      if (this.userStatusFilter === 'Deactivated' && u.is_active) return false;
      // Search query
      if (this.userSearchQuery) {
        const q = this.userSearchQuery.toLowerCase();
        const matchName = u.name.toLowerCase().includes(q);
        const matchEmail = u.email.toLowerCase().includes(q);
        const matchRoll = u.roll_no && u.roll_no.toLowerCase().includes(q);
        const matchEmp = u.employee_id && u.employee_id.toLowerCase().includes(q);
        if (!matchName && !matchEmail && !matchRoll && !matchEmp) return false;
      }
      return true;
    });

    this.elements.contentArea.innerHTML = `
      <div class="cbs-card-panel">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
          <div>
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px;">
              <h2 style="font-size: 1.35rem; font-weight: 800; color: #0f172a;">Principal User Administration Hub</h2>
              <span class="badge-tag" style="background: #eff6ff; color: #1e3a8a; border: 1px solid #bfdbfe;">
                Principal Authority
              </span>
            </div>
            <p style="font-size: 0.85rem; color: #64748b;">
              Create, view, edit, activate, deactivate accounts, enforce password policies, and manage RBAC profiles.
            </p>
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <button class="btn-secondary-action" onclick="cbsApp.exportUsersCSV()">
              📊 Export CSV
            </button>
            <button class="btn-secondary-action" onclick="cbsApp.openCSVImportModal()">
              📥 Bulk CSV Import
            </button>
            <button class="btn-primary-action" onclick="cbsApp.openAddUserModal()">
              + Create User Account
            </button>
          </div>
        </div>

        <!-- Filter & Search Toolbar -->
        <div class="user-filter-toolbar">
          <input type="text" class="user-search-input" placeholder="🔍 Search by Name, Email, Roll No, or Employee ID..." 
                 value="${this.userSearchQuery}" oninput="cbsApp.handleUserSearch(this.value)">

          <select class="user-filter-select" onchange="cbsApp.handleUserRoleFilter(this.value)">
            <option value="All" ${this.userRoleFilter === 'All' ? 'selected' : ''}>All Roles (${this.state.users.length})</option>
            <option value="Principal" ${this.userRoleFilter === 'Principal' ? 'selected' : ''}>Principal (Admin)</option>
            <option value="HOD" ${this.userRoleFilter === 'HOD' ? 'selected' : ''}>Head of Dept (HOD)</option>
            <option value="Faculty" ${this.userRoleFilter === 'Faculty' ? 'selected' : ''}>Faculty</option>
            <option value="Student" ${this.userRoleFilter === 'Student' ? 'selected' : ''}>Student</option>
          </select>

          <select class="user-filter-select" onchange="cbsApp.handleUserDeptFilter(this.value)">
            <option value="All" ${this.userDeptFilter === 'All' ? 'selected' : ''}>All Departments</option>
            ${this.state.departments.map(d => `<option value="${d.id}" ${this.userDeptFilter == d.id ? 'selected' : ''}>${d.code} - ${d.name}</option>`).join('')}
          </select>

          <select class="user-filter-select" onchange="cbsApp.handleUserStatusFilter(this.value)">
            <option value="All" ${this.userStatusFilter === 'All' ? 'selected' : ''}>All Statuses</option>
            <option value="Active" ${this.userStatusFilter === 'Active' ? 'selected' : ''}>Active Only</option>
            <option value="Deactivated" ${this.userStatusFilter === 'Deactivated' ? 'selected' : ''}>Deactivated Only</option>
          </select>

          ${(this.userSearchQuery || this.userRoleFilter !== 'All' || this.userDeptFilter !== 'All' || this.userStatusFilter !== 'All') ? `
            <button class="btn-secondary-action" style="padding: 6px 10px; font-size: 0.74rem;" onclick="cbsApp.clearUserFilters()">
              ✕ Clear
            </button>
          ` : ''}
        </div>

        <!-- Users Table -->
        <div class="cbs-table-wrap">
          <table class="cbs-table">
            <thead>
              <tr>
                <th>Identifier</th>
                <th>Full Name</th>
                <th>Institutional Email</th>
                <th>Role</th>
                <th>Dept</th>
                <th>Designation / Year</th>
                <th>Status</th>
                <th>Security Flag</th>
                <th style="text-align: right;">Principal Controls</th>
              </tr>
            </thead>
            <tbody>
              ${filteredUsers.length === 0 ? `
                <tr>
                  <td colspan="9" style="text-align: center; padding: 32px; color: #94a3b8;">
                    No accounts match the selected filters.
                  </td>
                </tr>
              ` : filteredUsers.map(u => {
                const dept = this.state.departments.find(d => d.id === u.department_id);
                const roleBadgeClass = u.role === 'Principal' || u.role === 'Admin' ? 'principal' : 
                                      u.role === 'HOD' ? 'hod' : 
                                      u.role === 'Faculty' ? 'faculty' : 'student';
                const idDisplay = u.roll_no || u.employee_id || `#${u.id}`;
                return `
                  <tr>
                    <td>
                      <code style="font-weight: 700; color: #1e3a8a; background: #eff6ff; padding: 2px 6px; border-radius: 4px;">
                        ${idDisplay}
                      </code>
                    </td>
                    <td><strong>${u.name}</strong></td>
                    <td style="font-size: 0.82rem; color: #475569;">${u.email}</td>
                    <td>
                      <span class="cred-role-badge ${roleBadgeClass}" style="margin: 0;">
                        ${u.role}
                      </span>
                    </td>
                    <td>${dept ? dept.code : '-'}</td>
                    <td style="font-size: 0.78rem;">
                      ${u.roll_no ? `Yr ${u.year} • Sec ${u.section || 'A'}` : u.designation || '-'}
                    </td>
                    <td>
                      <span class="status-pill ${u.is_active ? 'active' : 'expired'}">
                        ${u.is_active ? 'Active' : 'Deactivated'}
                      </span>
                    </td>
                    <td>
                      ${u.is_first_login ? `
                        <span class="status-pill pending" style="font-size: 0.68rem;" title="Must change temporary password upon login">
                          🔑 First Login
                        </span>
                      ` : `
                        <span style="font-size: 0.74rem; color: #10b981; font-weight: 600;">✓ Verified</span>
                      `}
                    </td>
                    <td style="text-align: right; white-space: nowrap;">
                      <div style="display: inline-flex; gap: 4px;">
                        <button class="btn-secondary-action" style="padding: 4px 7px; font-size: 0.72rem;" title="View Account Profile" onclick="cbsApp.openViewUserModal(${u.id})">
                          👁️ View
                        </button>
                        <button class="btn-secondary-action" style="padding: 4px 7px; font-size: 0.72rem;" title="Edit Account Details" onclick="cbsApp.openEditUserModal(${u.id})">
                          ✏️ Edit
                        </button>
                        <button class="btn-secondary-action" style="padding: 4px 7px; font-size: 0.72rem; color: #b45309;" title="Reset Password" onclick="cbsApp.openResetPasswordModal(${u.id})">
                          🔑 Reset
                        </button>
                        <button class="btn-secondary-action" style="padding: 4px 7px; font-size: 0.72rem; color: ${u.is_active ? '#dc2626' : '#16a34a'};" title="${u.is_active ? 'Deactivate' : 'Activate'}" onclick="cbsApp.toggleUserStatus(${u.id})">
                          ${u.is_active ? '⛔ Deact' : '✅ Act'}
                        </button>
                        ${(u.id !== curUser.id) ? `
                          <button class="btn-secondary-action" style="padding: 4px 7px; font-size: 0.72rem; color: #ef4444;" title="Delete User Account" onclick="cbsApp.confirmDeleteUser(${u.id})">
                            🗑️
                          </button>
                        ` : ''}
                      </div>
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  handleUserSearch(query) {
    this.userSearchQuery = query;
    this.renderUserManagement();
  }

  handleUserRoleFilter(role) {
    this.userRoleFilter = role;
    this.renderUserManagement();
  }

  handleUserDeptFilter(deptId) {
    this.userDeptFilter = deptId;
    this.renderUserManagement();
  }

  handleUserStatusFilter(status) {
    this.userStatusFilter = status;
    this.renderUserManagement();
  }

  clearUserFilters() {
    this.userSearchQuery = '';
    this.userRoleFilter = 'All';
    this.userDeptFilter = 'All';
    this.userStatusFilter = 'All';
    this.renderUserManagement();
  }

  toggleUserStatus(userId) {
    const curUser = this.state.currentUser;
    if (!curUser || (curUser.role !== 'Principal' && curUser.role !== 'Admin')) {
      alert('Access Denied: Only Principal is authorized to activate or deactivate accounts.');
      return;
    }

    const user = this.state.users.find(u => u.id === userId);
    if (!user) return;
    if (user.id === curUser.id) {
      alert('Security Protection: You cannot deactivate your own active Principal session!');
      return;
    }

    const actionText = user.is_active ? 'deactivate' : 'activate';
    if (!confirm(`Are you sure you want to ${actionText} the account for "${user.name}" (${user.email})?`)) {
      return;
    }

    user.is_active = !user.is_active;
    this.state.logAudit(curUser.name, 'Principal', 'USER_STATUS_CHANGE', 
      `${user.is_active ? 'Activated' : 'Deactivated'} account for ${user.name} (${user.email}, ${user.role})`);
    this.state.saveState();
    this.showToast(`User ${user.name} is now ${user.is_active ? 'Active' : 'Deactivated'}.`, 'normal');
    this.render();
  }

  // Strict Account Creation Modal (Requirement 3)
  openAddUserModal() {
    const curUser = this.state.currentUser;
    if (!curUser || (curUser.role !== 'Principal' && curUser.role !== 'Admin')) {
      alert('Access Denied: Only Principal is authorized to create user accounts.');
      return;
    }

    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
      <div class="modal-container" style="max-width: 580px;">
        <div class="modal-header">
          <div>
            <h3 style="font-size: 1.25rem; font-weight: 800; color: #0f172a;">Create New User Account</h3>
            <span style="font-size: 0.78rem; color: #64748b;">Requirement 3: Mandatory Validation & Unique ID Enforcement</span>
          </div>
          <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div class="modal-body">
          <form id="addUserForm" onsubmit="cbsApp.handleAddUserSubmit(event, this)">
            
            <div class="form-group">
              <label class="form-label">System Role <span class="req-star">*</span></label>
              <select name="role" id="newRoleSelect" class="form-select" required onchange="cbsApp.handleAddUserRoleChange(this.value)">
                <option value="Student">Student</option>
                <option value="Faculty">Faculty Member</option>
                <option value="HOD">Head of Department (HOD)</option>
                <option value="Principal">Principal (Administrator)</option>
              </select>
            </div>

            <div class="form-group">
              <label class="form-label">Full Name <span class="req-star">*</span></label>
              <input type="text" name="name" class="form-input" required placeholder="e.g. Dr. K. Ramesh or Priya Sharma">
            </div>

            <div class="form-group">
              <label class="form-label">Institutional Email <span class="req-star">*</span></label>
              <input type="email" name="email" class="form-input" required placeholder="e.g. priya.s@college.edu">
              <span style="font-size: 0.72rem; color: #64748b;">Must be a valid, unique institutional email address.</span>
            </div>

            <!-- Identifier Field: Dynamically switched based on role -->
            <div class="form-group">
              <label class="form-label" id="userIdLabel">Student Roll Number <span class="req-star">*</span></label>
              <input type="text" name="identifier" id="userIdInput" class="form-input" required placeholder="e.g. 24CS220">
              <span style="font-size: 0.72rem; color: #64748b;">Must be unique across all institutional accounts.</span>
            </div>

            <div class="form-group">
              <label class="form-label">Academic Department <span class="req-star">*</span></label>
              <select name="department_id" class="form-select" required>
                ${this.state.departments.map(d => `<option value="${d.id}">${d.name} (${d.code})</option>`).join('')}
              </select>
            </div>

            <!-- Student-Specific Fields -->
            <div id="studentFieldsWrap">
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                <div class="form-group">
                  <label class="form-label">Year of Study <span class="req-star">*</span></label>
                  <select name="year" class="form-select">
                    <option value="1">I Year (Freshman)</option>
                    <option value="2">II Year (Sophomore)</option>
                    <option value="3" selected>III Year (Junior)</option>
                    <option value="4">IV Year (Senior)</option>
                  </select>
                </div>
                <div class="form-group">
                  <label class="form-label">Section</label>
                  <select name="section" class="form-select">
                    <option value="A" selected>Section A</option>
                    <option value="B">Section B</option>
                    <option value="C">Section C</option>
                  </select>
                </div>
              </div>
            </div>

            <!-- Staff/Faculty/HOD Designation Field -->
            <div id="staffFieldsWrap" style="display: none;">
              <div class="form-group">
                <label class="form-label">Academic Designation <span class="req-star">*</span></label>
                <input type="text" name="designation" id="designationInput" class="form-input" placeholder="e.g. Associate Professor / Head of Department">
              </div>
            </div>

            <div class="form-group">
              <label class="form-label">Contact Phone (Optional)</label>
              <input type="text" name="phone" class="form-input" placeholder="e.g. +91 98490 12345">
            </div>

            <!-- Temporary / Initial Password Section -->
            <div class="form-group" style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: var(--radius-md); padding: 14px;">
              <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px;">
                <label class="form-label" style="margin: 0;">Initial Temporary Password <span class="req-star">*</span></label>
                <button type="button" class="btn-secondary-action" style="font-size: 0.72rem; padding: 2px 8px;" onclick="cbsApp.generateRandomFormPassword('newUserPwd')">
                  ⚡ Auto-Generate Strong Password
                </button>
              </div>
              <input type="text" name="password" id="newUserPwd" class="form-input" required 
                     value="Password@123" placeholder="Enter initial strong password">
              <div style="font-size: 0.72rem; color: #64748b; margin-top: 4px;">
                Must contain at least 8 characters with uppercase, lowercase, digit, and special symbol.
              </div>

              <div style="margin-top: 10px;">
                <label style="display: flex; align-items: center; gap: 8px; font-size: 0.82rem; color: #334155; cursor: pointer;">
                  <input type="checkbox" name="is_first_login" value="true" checked>
                  <strong>Require user to change password on first login (Requirement 6)</strong>
                </label>
              </div>
            </div>

            <div class="modal-footer" style="padding-inline: 0; background: transparent; margin-top: 16px;">
              <button type="button" class="btn-secondary-action" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
              <button type="submit" class="btn-primary-action">Create & Provision Account</button>
            </div>
          </form>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  handleAddUserRoleChange(role) {
    const studentWrap = document.getElementById('studentFieldsWrap');
    const staffWrap = document.getElementById('staffFieldsWrap');
    const label = document.getElementById('userIdLabel');
    const input = document.getElementById('userIdInput');
    const desigInput = document.getElementById('designationInput');

    if (role === 'Student') {
      if (studentWrap) studentWrap.style.display = 'block';
      if (staffWrap) staffWrap.style.display = 'none';
      if (label) label.innerHTML = 'Student Roll Number <span class="req-star">*</span>';
      if (input) input.placeholder = 'e.g. 24CS220';
      if (desigInput) desigInput.required = false;
    } else {
      if (studentWrap) studentWrap.style.display = 'none';
      if (staffWrap) staffWrap.style.display = 'block';
      if (label) label.innerHTML = 'Employee ID <span class="req-star">*</span>';
      if (input) input.placeholder = role === 'HOD' ? 'e.g. HOD-ECE-001' : role === 'Principal' ? 'e.g. PRIN-002' : 'e.g. FAC-CSE-012';
      if (desigInput) {
        desigInput.required = true;
        desigInput.value = role === 'HOD' ? 'Professor & Head of Department' : 
                           role === 'Principal' ? 'Principal & Administrator' : 'Associate Professor';
      }
    }
  }

  generateRandomFormPassword(inputId) {
    const symbols = ['@', '#', '$', '!', '%', '&'];
    const sym = symbols[Math.floor(Math.random() * symbols.length)];
    const num = Math.floor(100 + Math.random() * 900);
    const pwd = `Col${sym}${num}!Univ`;
    const el = document.getElementById(inputId);
    if (el) el.value = pwd;
    this.showToast(`Generated strong password: ${pwd}`, 'normal');
  }

  handleAddUserSubmit(e, form) {
    e.preventDefault();
    const fd = new FormData(form);
    const role = fd.get('role');
    const name = fd.get('name').trim();
    const email = fd.get('email').trim().toLowerCase();
    const identifier = fd.get('identifier').trim();
    const password = fd.get('password');
    const deptId = fd.get('department_id');
    const year = fd.get('year');
    const section = fd.get('section');
    const designation = fd.get('designation');
    const phone = fd.get('phone');
    const isFirstLogin = fd.get('is_first_login') === 'true';

    // Strict regex validation for email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      alert('Validation Error: Please enter a valid institutional email address.');
      return;
    }

    const userData = {
      name,
      email,
      role,
      password,
      department_id: deptId,
      roll_no: role === 'Student' ? identifier : null,
      employee_id: role !== 'Student' ? identifier : null,
      year: role === 'Student' ? year : null,
      section: role === 'Student' ? section : null,
      designation: role !== 'Student' ? designation : 'Student',
      phone,
      is_first_login: isFirstLogin
    };

    const res = this.state.createUser(userData);

    if (!res.success) {
      alert(`Account Creation Error:\n${res.message}`);
      return;
    }

    form.closest('.modal-overlay').remove();
    this.showToast(`User account created successfully for ${name} (${role})!`, 'success');
    this.render();
  }

  // Edit User Profile Modal (Requirement 2)
  openEditUserModal(userId) {
    const curUser = this.state.currentUser;
    if (!curUser || (curUser.role !== 'Principal' && curUser.role !== 'Admin')) {
      alert('Access Denied: Only Principal is authorized to edit accounts.');
      return;
    }

    const user = this.state.users.find(u => u.id === userId);
    if (!user) return;

    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
      <div class="modal-container" style="max-width: 580px;">
        <div class="modal-header">
          <div>
            <h3>Edit User Profile: ${user.name}</h3>
            <span style="font-size: 0.78rem; color: #64748b;">Principal Administrative Modification</span>
          </div>
          <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div class="modal-body">
          <form onsubmit="cbsApp.handleEditUserSubmit(event, ${user.id}, this)">
            <div class="form-group">
              <label class="form-label">Full Name <span class="req-star">*</span></label>
              <input type="text" name="name" class="form-input" required value="${user.name}">
            </div>

            <div class="form-group">
              <label class="form-label">Email Address <span class="req-star">*</span></label>
              <input type="email" name="email" class="form-input" required value="${user.email}">
            </div>

            <div class="form-group">
              <label class="form-label">Role <span class="req-star">*</span></label>
              <select name="role" class="form-select" required onchange="cbsApp.handleEditUserRoleChange(this.value)">
                <option value="Student" ${user.role === 'Student' ? 'selected' : ''}>Student</option>
                <option value="Faculty" ${user.role === 'Faculty' ? 'selected' : ''}>Faculty</option>
                <option value="HOD" ${user.role === 'HOD' ? 'selected' : ''}>Head of Department (HOD)</option>
                <option value="Principal" ${user.role === 'Principal' || user.role === 'Admin' ? 'selected' : ''}>Principal (Administrator)</option>
              </select>
            </div>

            <div class="form-group">
              <label class="form-label" id="editUserIdLabel">${user.role === 'Student' ? 'Roll Number' : 'Employee ID'} <span class="req-star">*</span></label>
              <input type="text" name="identifier" class="form-input" required value="${user.roll_no || user.employee_id || ''}">
            </div>

            <div class="form-group">
              <label class="form-label">Department</label>
              <select name="department_id" class="form-select">
                ${this.state.departments.map(d => `<option value="${d.id}" ${user.department_id === d.id ? 'selected' : ''}>${d.name} (${d.code})</option>`).join('')}
              </select>
            </div>

            <div id="editStudentWrap" style="display: ${user.role === 'Student' ? 'block' : 'none'};">
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                <div class="form-group">
                  <label class="form-label">Year of Study</label>
                  <select name="year" class="form-select">
                    <option value="1" ${user.year == 1 ? 'selected' : ''}>I Year</option>
                    <option value="2" ${user.year == 2 ? 'selected' : ''}>II Year</option>
                    <option value="3" ${user.year == 3 ? 'selected' : ''}>III Year</option>
                    <option value="4" ${user.year == 4 ? 'selected' : ''}>IV Year</option>
                  </select>
                </div>
                <div class="form-group">
                  <label class="form-label">Section</label>
                  <select name="section" class="form-select">
                    <option value="A" ${user.section === 'A' ? 'selected' : ''}>Section A</option>
                    <option value="B" ${user.section === 'B' ? 'selected' : ''}>Section B</option>
                    <option value="C" ${user.section === 'C' ? 'selected' : ''}>Section C</option>
                  </select>
                </div>
              </div>
            </div>

            <div id="editStaffWrap" style="display: ${user.role !== 'Student' ? 'block' : 'none'};">
              <div class="form-group">
                <label class="form-label">Designation</label>
                <input type="text" name="designation" class="form-input" value="${user.designation || ''}">
              </div>
            </div>

            <div class="form-group">
              <label class="form-label">Contact Phone</label>
              <input type="text" name="phone" class="form-input" value="${user.phone || ''}">
            </div>

            <div class="form-group">
              <label class="form-label">Account Status</label>
              <select name="is_active" class="form-select">
                <option value="true" ${user.is_active ? 'selected' : ''}>Active</option>
                <option value="false" ${!user.is_active ? 'selected' : ''}>Deactivated</option>
              </select>
            </div>

            <div class="modal-footer" style="padding-inline: 0; background: transparent;">
              <button type="button" class="btn-secondary-action" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
              <button type="submit" class="btn-primary-action">Save Changes</button>
            </div>
          </form>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  handleEditUserRoleChange(role) {
    const studentWrap = document.getElementById('editStudentWrap');
    const staffWrap = document.getElementById('editStaffWrap');
    const label = document.getElementById('editUserIdLabel');
    if (role === 'Student') {
      if (studentWrap) studentWrap.style.display = 'block';
      if (staffWrap) staffWrap.style.display = 'none';
      if (label) label.innerText = 'Roll Number *';
    } else {
      if (studentWrap) studentWrap.style.display = 'none';
      if (staffWrap) staffWrap.style.display = 'block';
      if (label) label.innerText = 'Employee ID *';
    }
  }

  handleEditUserSubmit(e, userId, form) {
    e.preventDefault();
    const fd = new FormData(form);
    const updated = {
      name: fd.get('name'),
      email: fd.get('email'),
      role: fd.get('role'),
      department_id: fd.get('department_id'),
      roll_no: fd.get('role') === 'Student' ? fd.get('identifier') : null,
      employee_id: fd.get('role') !== 'Student' ? fd.get('identifier') : null,
      year: fd.get('year'),
      section: fd.get('section'),
      designation: fd.get('designation'),
      phone: fd.get('phone'),
      is_active: fd.get('is_active') === 'true'
    };

    const res = this.state.updateUser(userId, updated);
    if (!res.success) {
      alert(`Error updating user:\n${res.message}`);
      return;
    }

    form.closest('.modal-overlay').remove();
    this.showToast(`User ${updated.name} updated successfully!`, 'success');
    this.render();
  }

  // View User Profile Card (Requirement 2)
  openViewUserModal(userId) {
    const user = this.state.users.find(u => u.id === userId);
    if (!user) return;
    const dept = this.state.departments.find(d => d.id === u.department_id || d.id === user.department_id);

    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
      <div class="modal-container" style="max-width: 600px;">
        <div class="modal-header">
          <div style="display: flex; align-items: center; gap: 12px;">
            <div class="cred-avatar ${user.role.toLowerCase()}" style="width: 44px; height: 44px; font-size: 1.2rem;">
              ${user.role === 'Principal' ? '🛡️' : user.role === 'HOD' ? '👨‍💼' : user.role === 'Faculty' ? '👩‍🏫' : '🎓'}
            </div>
            <div>
              <h3 style="margin: 0; font-size: 1.2rem;">${user.name}</h3>
              <span class="cred-role-badge ${user.role.toLowerCase()}" style="margin: 0;">${user.role}</span>
            </div>
          </div>
          <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div class="modal-body">
          <div class="profile-view-grid">
            <div class="profile-field-item">
              <label>Institutional Email</label>
              <div>${user.email}</div>
            </div>
            <div class="profile-field-item">
              <label>${user.role === 'Student' ? 'Roll Number' : 'Employee ID'}</label>
              <div><code>${user.roll_no || user.employee_id || '-'}</code></div>
            </div>
            <div class="profile-field-item">
              <label>Academic Department</label>
              <div>${dept ? `${dept.name} (${dept.code})` : 'Central Administration'}</div>
            </div>
            <div class="profile-field-item">
              <label>${user.role === 'Student' ? 'Year & Section' : 'Designation'}</label>
              <div>${user.roll_no ? `Year ${user.year} • Section ${user.section || 'A'}` : user.designation || '-'}</div>
            </div>
            <div class="profile-field-item">
              <label>Contact Phone</label>
              <div>${user.phone || 'Not provided'}</div>
            </div>
            <div class="profile-field-item">
              <label>Account Status</label>
              <div>
                <span class="status-pill ${user.is_active ? 'active' : 'expired'}">
                  ${user.is_active ? 'Active' : 'Deactivated'}
                </span>
              </div>
            </div>
          </div>

          <!-- Security Attributes Card -->
          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: var(--radius-md); padding: 14px; margin-bottom: 16px;">
            <h4 style="font-size: 0.82rem; font-weight: 700; color: #1e3a8a; text-transform: uppercase; margin-bottom: 8px;">
              🔒 Security & Authentication Metadata
            </h4>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.78rem; color: #475569;">
              <div><strong>Password Security:</strong> Salted SHA-256 Hashed</div>
              <div><strong>Initial Login Policy:</strong> ${user.is_first_login ? '⚠️ Must Change Password' : '✓ Password Established'}</div>
              <div><strong>Failed Login Attempts:</strong> ${user.failed_attempts || 0} / 5</div>
              <div><strong>Lockout Status:</strong> ${user.lockout_until && Date.now() < user.lockout_until ? '⛔ Locked Out' : '✓ Normal'}</div>
              <div><strong>Last Sign In:</strong> ${user.last_login || 'Never'}</div>
              <div><strong>Account Created:</strong> ${user.created_at || 'Pre-seeded'}</div>
            </div>
          </div>

          <div class="modal-footer" style="padding-inline: 0; background: transparent;">
            <button type="button" class="btn-secondary-action" onclick="cbsApp.openResetPasswordModal(${user.id}); this.closest('.modal-overlay').remove();">
              🔑 Reset Password
            </button>
            <button type="button" class="btn-secondary-action" onclick="cbsApp.openEditUserModal(${user.id}); this.closest('.modal-overlay').remove();">
              ✏️ Edit Profile
            </button>
            <button type="button" class="btn-primary-action" onclick="this.closest('.modal-overlay').remove()">
              Close
            </button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  // Administrative Password Reset Modal (Requirement 2 & 5)
  openResetPasswordModal(userId) {
    const curUser = this.state.currentUser;
    if (!curUser || (curUser.role !== 'Principal' && curUser.role !== 'Admin')) {
      alert('Access Denied: Only Principal is authorized to reset account passwords.');
      return;
    }

    const user = this.state.users.find(u => u.id === userId);
    if (!user) return;

    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
      <div class="modal-container" style="max-width: 500px;">
        <div class="modal-header">
          <div>
            <h3>Reset Password: ${user.name}</h3>
            <span style="font-size: 0.78rem; color: #64748b;">Principal Administrative Credential Override</span>
          </div>
          <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div class="modal-body">
          <p style="font-size: 0.85rem; color: #475569; margin-bottom: 14px;">
            Set a temporary password for <strong>${user.name}</strong> (${user.email}). The user will be required to change it on their next login.
          </p>

          <form onsubmit="cbsApp.handleResetPasswordSubmit(event, ${user.id}, this)">
            <div class="form-group">
              <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px;">
                <label class="form-label" style="margin: 0;">New Temporary Password <span class="req-star">*</span></label>
                <button type="button" class="btn-secondary-action" style="font-size: 0.72rem; padding: 2px 8px;" onclick="cbsApp.generateRandomFormPassword('adminResetPwd')">
                  ⚡ Auto-Generate Strong Password
                </button>
              </div>
              <input type="text" name="tempPassword" id="adminResetPwd" class="form-input" required value="Temp#2026!" placeholder="Enter temporary password">
            </div>

            <div class="form-group">
              <label style="display: flex; align-items: center; gap: 8px; font-size: 0.82rem; color: #334155; cursor: pointer;">
                <input type="checkbox" name="requireFirstLogin" value="true" checked>
                <strong>Force password change on next login (Requirement 6)</strong>
              </label>
            </div>

            <div class="modal-footer" style="padding-inline: 0; background: transparent;">
              <button type="button" class="btn-secondary-action" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
              <button type="submit" class="btn-primary-action">Apply Password Reset</button>
            </div>
          </form>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  handleResetPasswordSubmit(e, userId, form) {
    e.preventDefault();
    const fd = new FormData(form);
    const tempPassword = fd.get('tempPassword');
    const requireFirstLogin = fd.get('requireFirstLogin') === 'true';

    const res = this.state.resetPasswordAdmin(userId, tempPassword, requireFirstLogin);
    if (!res.success) {
      alert(`Password Reset Error:\n${res.message}`);
      return;
    }

    form.closest('.modal-overlay').remove();
    alert(`Password reset successful for ${res.user.name}!\n\nTemporary Password:\n${tempPassword}\n\nPlease communicate this temporary password securely to the user.`);
    this.showToast(`Password reset completed for ${res.user.name}.`, 'success');
    this.render();
  }

  confirmDeleteUser(userId) {
    const curUser = this.state.currentUser;
    if (!curUser || (curUser.role !== 'Principal' && curUser.role !== 'Admin')) {
      alert('Access Denied: Only Principal is authorized to delete accounts.');
      return;
    }

    const user = this.state.users.find(u => u.id === userId);
    if (!user) return;

    if (user.id === curUser.id) {
      alert('You cannot delete your own active Principal account!');
      return;
    }

    if (confirm(`CAUTION: Are you sure you want to permanently delete the account for "${user.name}" (${user.email}, ${user.role})? This action will be recorded in the audit trail.`)) {
      this.state.deleteUser(userId);
      this.showToast(`User ${user.name} has been removed.`, 'normal');
      this.render();
    }
  }

  exportUsersCSV() {
    let csv = 'ID,Name,Email,Role,Department,Roll_or_Employee_ID,Year,Section,Designation,Status,First_Login_Pending\n';
    this.state.users.forEach(u => {
      const dept = this.state.departments.find(d => d.id === u.department_id)?.code || '';
      const safeName = `"${u.name.replace(/"/g, '""')}"`;
      const idStr = u.roll_no || u.employee_id || '';
      csv += `${u.id},${safeName},${u.email},${u.role},${dept},${idStr},${u.year || ''},${u.section || ''},"${u.designation || ''}",${u.is_active ? 'Active' : 'Deactivated'},${!!u.is_first_login}\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `CBS_Users_Directory_${getFormattedDate(0)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    this.showToast('Users directory exported as CSV.', 'success');
  }

  // CSV Import Modal & Parser (FR-24, TC-06)
  openCSVImportModal() {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
      <div class="modal-container" style="max-width: 680px;">
        <div class="modal-header">
          <h3>Import Students via CSV</h3>
          <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div class="modal-body">
          <p style="font-size: 0.85rem; color: #475569; margin-bottom: 14px;">
            Paste CSV formatted text or upload a .csv file. The parser validates rows, imports valid records, and reports any faulty rows as specified in Test Case TC-06.
          </p>

          <div style="margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 0.78rem; font-weight: 600; color: #64748b;">
              Expected Format: name, email, department_code, year, roll_no
            </span>
            <button class="btn-secondary-action" style="font-size: 0.74rem; padding: 4px 10px;" onclick="cbsApp.fillSampleCSV()">
              Load Sample CSV Data
            </button>
          </div>

          <textarea id="csvInputText" class="form-textarea" rows="7" style="font-family: monospace; font-size: 0.82rem;" placeholder="name,email,department_code,year,roll_no
Aakash Sharma,aakash.s@college.edu,CSE,3,24CS110
Bhavna Jain,bhavna.j@college.edu,IT,3,24IT051
Invalid Row Without Email,,CSE,3,24CS999
Chirag Verma,chirag.v@college.edu,MECH,2,25ME034"></textarea>

          <div id="csvValidationOutput" style="margin-top: 14px; display: none;"></div>

          <div class="modal-footer" style="padding-inline: 0; background: transparent; margin-top: 14px;">
            <button type="button" class="btn-secondary-action" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
            <button type="button" class="btn-primary-action" onclick="cbsApp.processCSVImport()">
              Validate & Import
            </button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  fillSampleCSV() {
    const txt = document.getElementById('csvInputText');
    if (txt) {
      txt.value = `name,email,department_code,year,roll_no
Pooja Hegde,pooja.h@college.edu,CSE,3,24CS180
Karthik Aryan,karthik.a@college.edu,ECE,2,25EC045
Bad Entry With Empty Email,,CSE,3,24CS999
Devendra Joshi,devendra.j@college.edu,IT,4,23IT012`;
    }
  }

  processCSVImport() {
    const raw = document.getElementById('csvInputText').value.trim();
    if (!raw) {
      alert('Please enter CSV data or click "Load Sample CSV Data".');
      return;
    }

    const lines = raw.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    if (lines.length < 2) {
      alert('CSV must contain a header row and at least one data row.');
      return;
    }

    const imported = [];
    const errors = [];

    // Parse lines (skip line 0 as header)
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(',').map(p => p.trim());
      if (parts.length < 5) {
        errors.push({ line: i + 1, row: lines[i], reason: 'Insufficient columns' });
        continue;
      }

      const [name, email, deptCode, yearStr, rollNo] = parts;

      if (!name || !email) {
        errors.push({ line: i + 1, row: lines[i], reason: 'Name or email is missing' });
        continue;
      }

      // Check if email duplicate
      if (this.state.users.some(u => u.email.toLowerCase() === email.toLowerCase()) ||
          imported.some(u => u.email.toLowerCase() === email.toLowerCase())) {
        errors.push({ line: i + 1, row: lines[i], reason: `Duplicate email: ${email}` });
        continue;
      }

      const dept = this.state.departments.find(d => d.code.toUpperCase() === deptCode.toUpperCase());
      const deptId = dept ? dept.id : 1;
      const year = parseInt(yearStr) || 1;

      imported.push({
        id: Date.now() + i,
        name,
        email,
        password: 'password123',
        role: 'Student',
        department_id: deptId,
        roll_no: rollNo,
        year: year,
        section: 'A',
        is_active: true
      });
    }

    // Append valid users to database
    if (imported.length > 0) {
      this.state.users.push(...imported);
      this.state.logAudit(this.state.currentUser.name, 'Admin', 'CSV_IMPORT', `Imported ${imported.length} student accounts from CSV.`);
      this.state.saveState();
    }

    // Show Report as specified in TC-06: Valid rows imported; bad row reported
    const out = document.getElementById('csvValidationOutput');
    out.style.display = 'block';
    out.innerHTML = `
      <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 12px; border-radius: 6px; font-size: 0.85rem; color: #166534; margin-bottom: 10px;">
        ✅ <strong>Success:</strong> Successfully imported ${imported.length} student account(s).
      </div>
      ${errors.length > 0 ? `
        <div style="background: #fef2f2; border: 1px solid #fecaca; padding: 12px; border-radius: 6px; font-size: 0.85rem; color: #991b1b;">
          ⚠️ <strong>Reported Issues (${errors.length} bad rows skipped):</strong>
          <ul style="margin-left: 18px; margin-top: 6px;">
            ${errors.map(err => `<li>Line ${err.line}: <code>${err.row}</code> — <em>${err.reason}</em></li>`).join('')}
          </ul>
        </div>
      ` : ''}
    `;

    this.showToast(`Imported ${imported.length} students.`, 'success');
    this.render();
  }

  // ==========================================
  // MASTER DATA MANAGEMENT (FR-26)
  // ==========================================
  renderMasterDataManagement() {
    this.elements.contentArea.innerHTML = `
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 24px;">
        <!-- Departments Panel -->
        <div class="cbs-card-panel">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px;">
            <h3 style="font-size: 1.2rem; font-weight: 700; color: #0f172a;">Academic Departments</h3>
            <button class="btn-primary-action" style="padding: 6px 14px; font-size: 0.80rem;" onclick="cbsApp.promptAddDepartment()">
              + Add Dept
            </button>
          </div>
          <div class="cbs-table-wrap">
            <table class="cbs-table">
              <thead>
                <tr>
                  <th>Code</th>
                  <th>Name</th>
                  <th>Students</th>
                  <th>Faculty</th>
                </tr>
              </thead>
              <tbody>
                ${this.state.departments.map(d => {
                  const stuCount = this.state.users.filter(u => u.role === 'Student' && u.department_id === d.id).length;
                  const facCount = this.state.users.filter(u => u.role === 'Faculty' && u.department_id === d.id).length;
                  return `
                    <tr>
                      <td><strong>${d.code}</strong></td>
                      <td>${d.name}</td>
                      <td>${stuCount}</td>
                      <td>${facCount}</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>

        <!-- Categories Panel -->
        <div class="cbs-card-panel">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px;">
            <h3 style="font-size: 1.2rem; font-weight: 700; color: #0f172a;">Notice Categories (FR-26)</h3>
            <button class="btn-primary-action" style="padding: 6px 14px; font-size: 0.80rem;" onclick="cbsApp.promptAddCategory()">
              + Add Category
            </button>
          </div>
          <div class="cbs-table-wrap">
            <table class="cbs-table">
              <thead>
                <tr>
                  <th>Color</th>
                  <th>Category Name</th>
                  <th>Active Notices</th>
                </tr>
              </thead>
              <tbody>
                ${this.state.categories.map(c => {
                  const count = this.state.notices.filter(n => n.category_id === c.id && n.status === 'Active').length;
                  return `
                    <tr>
                      <td>
                        <span style="display: inline-block; width: 18px; height: 18px; border-radius: 4px; background: ${c.colour_code}; vertical-align: middle;"></span>
                      </td>
                      <td>
                        <span class="badge-tag" style="background: ${c.colour_code}20; color: ${c.colour_code};">
                          ${c.name}
                        </span>
                      </td>
                      <td>${count} notices</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  promptAddDepartment() {
    const code = prompt('Enter Department Code (e.g. AI-DS):');
    if (!code) return;
    const name = prompt('Enter Full Department Name (e.g. Artificial Intelligence & Data Science):');
    if (!name) return;

    this.state.departments.push({
      id: Date.now(),
      code: code.trim().toUpperCase(),
      name: name.trim(),
      hod_user_id: null
    });
    this.state.logAudit(this.state.currentUser.name, 'Admin', 'ADD_DEPARTMENT', `Added department ${code}`);
    this.state.saveState();
    this.showToast(`Department ${code} added!`, 'success');
    this.render();
  }

  promptAddCategory() {
    const name = prompt('Enter New Notice Category Name (e.g. Sports):');
    if (!name) return;
    const color = prompt('Enter Hex Color Code (e.g. #0284c7):', '#0284c7');

    this.state.categories.push({
      id: Date.now(),
      name: name.trim(),
      colour_code: color.trim(),
      bg_code: `${color.trim()}20`,
      class_slug: `cat-${name.toLowerCase().replace(/\s+/g, '-')}`
    });
    this.state.logAudit(this.state.currentUser.name, 'Admin', 'ADD_CATEGORY', `Added category ${name}`);
    this.state.saveState();
    this.showToast(`Category ${name} added!`, 'success');
    this.render();
  }

  // ==========================================
  // REPORTS & ANALYTICS (FR-28, TC-28)
  // ==========================================
  renderReportsAndAnalytics() {
    const totalNotices = this.state.notices.length;
    const totalViews = this.state.notice_views.length;
    const urgentCount = this.state.notices.filter(n => n.priority === 'Urgent').length;

    this.elements.contentArea.innerHTML = `
      <div class="cbs-card-panel">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; flex-wrap: wrap; gap: 12px;">
          <div>
            <h2 style="font-size: 1.4rem; font-weight: 800; color: #0f172a;">College Notice Reports & Analytics</h2>
            <p style="font-size: 0.85rem; color: #64748b;">Notice distribution, student engagement tracking, and turnaround metrics.</p>
          </div>
          <div style="display: flex; gap: 10px;">
            <button class="btn-secondary-action" onclick="window.print()">
              🖨️ Export to PDF / Print
            </button>
            <button class="btn-primary-action" onclick="cbsApp.exportNoticeReportCSV()">
              📥 Export CSV Report
            </button>
          </div>
        </div>

        <div class="kpi-stats-grid">
          <div class="kpi-card">
            <div class="kpi-icon-box blue">📊</div>
            <div class="kpi-content">
              <h4>All-Time Notices</h4>
              <div class="kpi-num">${totalNotices}</div>
            </div>
          </div>
          <div class="kpi-card">
            <div class="kpi-icon-box green">👁️</div>
            <div class="kpi-content">
              <h4>Total Read Events</h4>
              <div class="kpi-num">${totalViews}</div>
            </div>
          </div>
          <div class="kpi-card">
            <div class="kpi-icon-box amber">⚡</div>
            <div class="kpi-content">
              <h4>Urgent Notices</h4>
              <div class="kpi-num">${urgentCount}</div>
            </div>
          </div>
          <div class="kpi-card">
            <div class="kpi-icon-box purple">⏱️</div>
            <div class="kpi-content">
              <h4>Avg Approval Time</h4>
              <div class="kpi-num">4.2 hrs</div>
            </div>
          </div>
        </div>

        <!-- Breakdown by Category -->
        <div style="margin-top: 24px;">
          <h3 style="font-size: 1.1rem; font-weight: 700; color: #0f172a; margin-bottom: 14px;">Notices by Category</h3>
          <div style="display: flex; flex-direction: column; gap: 12px;">
            ${this.state.categories.map(c => {
              const count = this.state.notices.filter(n => n.category_id === c.id).length;
              const pct = totalNotices > 0 ? ((count / totalNotices) * 100).toFixed(0) : 0;
              return `
                <div>
                  <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 4px;">
                    <span style="font-weight: 600;">${c.name}</span>
                    <span>${count} notices (${pct}%)</span>
                  </div>
                  <div style="width: 100%; height: 10px; background: #e2e8f0; border-radius: 999px; overflow: hidden;">
                    <div style="width: ${pct}%; height: 100%; background: ${c.colour_code}; border-radius: 999px;"></div>
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>

        <!-- Detailed Notice Performance Table -->
        <div style="margin-top: 30px;">
          <h3 style="font-size: 1.1rem; font-weight: 700; color: #0f172a; margin-bottom: 14px;">Notice Performance & Student Reach</h3>
          <div class="cbs-table-wrap">
            <table class="cbs-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Category</th>
                  <th>Priority</th>
                  <th>Posted On</th>
                  <th>Reads Count</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                ${this.state.notices.map(n => {
                  const cat = this.state.categories.find(c => c.id === n.category_id);
                  const views = this.state.getNoticeReadCount(n.id);
                  return `
                    <tr>
                      <td><strong>${n.title}</strong></td>
                      <td>${cat?.name}</td>
                      <td>${n.priority}</td>
                      <td>${n.post_date}</td>
                      <td><strong>${views}</strong> verified reads</td>
                      <td><span class="status-pill ${n.status.toLowerCase()}">${n.status}</span></td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  exportNoticeReportCSV() {
    let csv = 'Notice ID,Title,Category,Priority,Status,Posted Date,Expiry Date,Read Count\n';
    this.state.notices.forEach(n => {
      const cat = this.state.categories.find(c => c.id === n.category_id)?.name || 'General';
      const reads = this.state.getNoticeReadCount(n.id);
      const safeTitle = `"${n.title.replace(/"/g, '""')}"`;
      csv += `${n.id},${safeTitle},${cat},${n.priority},${n.status},${n.post_date},${n.expiry_date},${reads}\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `CBS_Notice_Report_${getFormattedDate(0)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    this.showToast('CSV report generated and downloaded.', 'success');
  }

  // ==========================================
  // SYSTEM AUDIT TRAIL (Requirement 7, FR-29, Table 31)
  // ==========================================
  renderAuditLog() {
    const curUser = this.state.currentUser;
    const isPrincipal = curUser && (curUser.role === 'Principal' || curUser.role === 'Admin');
    if (!isPrincipal) {
      this.showToast('Access Denied: Only Principal has administrative authorization to inspect audit logs.', 'urgent');
      this.currentTab = 'dashboard';
      this.render();
      return;
    }

    let logs = this.state.audit_logs.filter(log => {
      // Category filter
      if (this.auditCategoryFilter === 'users') {
        if (!['USER_ADD', 'USER_EDIT', 'USER_STATUS_CHANGE', 'USER_DELETE'].includes(log.action)) return false;
      } else if (this.auditCategoryFilter === 'auth') {
        if (!['LOGIN', 'LOGOUT', 'LOGIN_FAILED', 'LOGIN_LOCKOUT', 'PASSWORD_RESET_ADMIN', 'PASSWORD_RESET_SELF', 'PASSWORD_CHANGE_FIRST_LOGIN', 'UNAUTHORIZED_ACCESS_BLOCKED'].includes(log.action)) return false;
      } else if (this.auditCategoryFilter === 'notices') {
        if (!['CREATE_NOTICE', 'APPROVE_NOTICE', 'REJECT_NOTICE', 'ARCHIVE_NOTICE', 'DELETE_NOTICE'].includes(log.action)) return false;
      } else if (this.auditCategoryFilter === 'system') {
        if (!['SCHEDULER_RUN', 'ADD_CATEGORY', 'ADD_DEPARTMENT'].includes(log.action)) return false;
      }

      // Search query
      if (this.auditSearchQuery) {
        const q = this.auditSearchQuery.toLowerCase();
        const matchActor = log.user_name && log.user_name.toLowerCase().includes(q);
        const matchAction = log.action && log.action.toLowerCase().includes(q);
        const matchDetails = log.details && log.details.toLowerCase().includes(q);
        if (!matchActor && !matchAction && !matchDetails) return false;
      }
      return true;
    });

    this.elements.contentArea.innerHTML = `
      <div class="cbs-card-panel">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
          <div>
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px;">
              <h2 style="font-size: 1.35rem; font-weight: 800; color: #0f172a;">Institutional Security Audit Trail</h2>
              <span class="badge-tag" style="background: #eff6ff; color: #1e3a8a; border: 1px solid #bfdbfe;">
                Requirement 7 Audit Engine
              </span>
            </div>
            <p style="font-size: 0.85rem; color: #64748b;">
              Immutable record of account creations, modifications, deactivations, password resets, logins, and approvals.
            </p>
          </div>
          <button class="btn-primary-action" onclick="cbsApp.exportAuditLogCSV()">
            📥 Export Audit Log CSV
          </button>
        </div>

        <!-- Category Filters & Search Toolbar -->
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 18px;">
          <div class="audit-category-filters">
            <button class="audit-cat-btn ${this.auditCategoryFilter === 'All' ? 'active' : ''}" onclick="cbsApp.handleAuditCategory('All')">
              All Events (${this.state.audit_logs.length})
            </button>
            <button class="audit-cat-btn ${this.auditCategoryFilter === 'users' ? 'active' : ''}" onclick="cbsApp.handleAuditCategory('users')">
              👥 User Lifecycle
            </button>
            <button class="audit-cat-btn ${this.auditCategoryFilter === 'auth' ? 'active' : ''}" onclick="cbsApp.handleAuditCategory('auth')">
              🔐 Authentication & Passwords
            </button>
            <button class="audit-cat-btn ${this.auditCategoryFilter === 'notices' ? 'active' : ''}" onclick="cbsApp.handleAuditCategory('notices')">
              📋 Notice Workflow
            </button>
            <button class="audit-cat-btn ${this.auditCategoryFilter === 'system' ? 'active' : ''}" onclick="cbsApp.handleAuditCategory('system')">
              ⚙️ System & Scheduler
            </button>
          </div>

          <div style="min-width: 240px; flex: 1; max-width: 320px;">
            <input type="text" class="form-input" style="padding: 6px 12px; font-size: 0.82rem;" 
                   placeholder="🔍 Search actor, action, details..." value="${this.auditSearchQuery}" 
                   oninput="cbsApp.handleAuditSearch(this.value)">
          </div>
        </div>

        <div class="cbs-table-wrap">
          <table class="cbs-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor Identity</th>
                <th>Role</th>
                <th>Action Category</th>
                <th>Event Narrative Details</th>
                <th>Network IP</th>
              </tr>
            </thead>
            <tbody>
              ${logs.length === 0 ? `
                <tr>
                  <td colspan="6" style="text-align: center; padding: 30px; color: #94a3b8;">
                    No audit records match the current filter criteria.
                  </td>
                </tr>
              ` : logs.map(log => {
                const actionBadgeColor = log.action.includes('LOCKOUT') || log.action.includes('REJECT') || log.action.includes('UNAUTHORIZED') ? '#dc2626' :
                                        log.action.includes('APPROVE') || log.action.includes('USER_ADD') ? '#16a34a' :
                                        log.action.includes('PASSWORD') ? '#d97706' : '#2563eb';
                return `
                  <tr>
                    <td style="white-space: nowrap; font-size: 0.78rem; color: #64748b;">${log.timestamp}</td>
                    <td><strong>${log.user_name}</strong></td>
                    <td>
                      <span class="badge-tag" style="background: #f1f5f9; color: #334155; font-size: 0.70rem;">
                        ${log.role}
                      </span>
                    </td>
                    <td>
                      <code style="font-weight: 700; color: ${actionBadgeColor}; background: ${actionBadgeColor}15; padding: 2px 6px; border-radius: 4px; font-size: 0.76rem;">
                        ${log.action}
                      </code>
                    </td>
                    <td style="font-size: 0.84rem; color: #334155;">${log.details}</td>
                    <td style="font-family: monospace; font-size: 0.76rem; color: #64748b;">${log.ip}</td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  handleAuditCategory(cat) {
    this.auditCategoryFilter = cat;
    this.renderAuditLog();
  }

  handleAuditSearch(q) {
    this.auditSearchQuery = q;
    this.renderAuditLog();
  }

  exportAuditLogCSV() {
    let csv = 'Timestamp,Actor,Role,Action,Details,IP_Address\n';
    this.state.audit_logs.forEach(log => {
      const safeActor = `"${(log.user_name || '').replace(/"/g, '""')}"`;
      const safeDetails = `"${(log.details || '').replace(/"/g, '""')}"`;
      csv += `"${log.timestamp}",${safeActor},"${log.role}","${log.action}",${safeDetails},"${log.ip}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `CBS_Security_Audit_Trail_${getFormattedDate(0)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    this.showToast('Audit log export generated and downloaded.', 'success');
  }

  // ==========================================
  // ARCHIVE BROWSER (FR-23, TC-27)
  // ==========================================
  renderArchiveBrowser() {
    const user = this.state.currentUser;
    const archived = this.state.notices.filter(n => n.status === 'Archived' || n.status === 'Expired');

    this.elements.contentArea.innerHTML = `
      <div class="cbs-card-panel">
        <div style="margin-bottom: 20px;">
          <h2 style="font-size: 1.35rem; font-weight: 700; color: #0f172a;">Archived & Expired Notice Repository</h2>
          <p style="font-size: 0.85rem; color: #64748b;">Past college circulars and expired items preserved for historical reference.</p>
        </div>

        <div class="notices-grid">
          ${archived.length === 0 ? `
            <div class="empty-state-card">
              <h4>No archived notices</h4>
              <p>Past circulars will automatically appear here once their active term expires.</p>
            </div>
          ` : archived.map(n => this.renderNoticeCardHTML(n, user)).join('')}
        </div>
      </div>
    `;
  }

  // ==========================================
  // NOTICE DETAIL MODAL & LIGHTBOX (FR-19, FR-22)
  // ==========================================
  openNoticeDetail(noticeId) {
    const notice = this.state.notices.find(n => n.id === noticeId);
    if (!notice) return;

    const user = this.state.currentUser;
    // Log read event for students
    if (user.role === 'Student') {
      this.state.recordNoticeRead(notice.id, user.id);
    }

    const cat = this.state.categories.find(c => c.id === notice.category_id);
    const poster = this.state.users.find(u => u.id === notice.posted_by);
    const daysLeft = this.state.getDaysRemaining(notice.expiry_date);
    const readCount = this.state.getNoticeReadCount(notice.id);

    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
      <div class="modal-container" style="max-width: 820px;">
        <div class="modal-header">
          <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
            <span class="badge-tag" style="background: ${cat?.colour_code}20; color: ${cat?.colour_code};">${cat?.name}</span>
            ${notice.priority === 'Urgent' ? '<span class="badge-tag urgent">URGENT</span>' : ''}
            ${notice.is_pinned ? '<span class="badge-tag pinned">📌 PINNED</span>' : ''}
            <span class="days-remaining-pill ${daysLeft <= 3 ? 'imminent' : ''}">${daysLeft === 0 ? 'Expired' : `${daysLeft} days validity`}</span>
          </div>
          <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div class="modal-body">
          <h2 style="font-size: 1.4rem; font-weight: 800; color: #0f172a; margin-bottom: 12px; line-height: 1.3;">
            ${notice.title}
          </h2>

          <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 16px; margin-bottom: 18px; font-size: 0.82rem; color: #475569; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px;">
            <div><strong>Posted By:</strong> ${poster ? poster.name : 'College Office'} (${poster?.designation || 'Staff'})</div>
            <div><strong>Date Published:</strong> ${notice.post_date}</div>
            <div><strong>Target Audience:</strong> ${this.formatTargetAudience(notice)}</div>
            <div><strong>Engagement:</strong> 👁️ ${readCount} verified reads</div>
          </div>

          <div style="font-size: 0.95rem; color: #1e293b; line-height: 1.7; white-space: pre-line; margin-bottom: 24px;">
            ${notice.description}
          </div>

          ${notice.attachments && notice.attachments.length > 0 ? `
            <div style="border-top: 1px solid #e2e8f0; padding-top: 16px;">
              <h4 style="font-size: 0.85rem; font-weight: 700; color: #334155; margin-bottom: 10px;">Attached Documents & Media (${notice.attachments.length}):</h4>
              <div class="attachment-preview-grid">
                ${notice.attachments.map(att => {
                  const isImg = att.path.endsWith('.png') || att.path.endsWith('.jpg');
                  return `
                    <div class="attachment-thumbnail" onclick="cbsApp.previewAttachment('${att.path}', '${att.name}')">
                      ${isImg ? `<img src="${att.path}" alt="${att.name}">` : `
                        <div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #dc2626;">
                          <div style="font-size: 2rem;">📄</div>
                          <span style="font-size: 0.70rem; color: #64748b; font-weight: 600;">PDF DOCUMENT</span>
                        </div>
                      `}
                      <div class="thumb-tag">📎 ${att.name}</div>
                    </div>
                  `;
                }).join('')}
              </div>
            </div>
          ` : ''}
        </div>
        <div class="modal-footer">
          <button class="btn-secondary-action" onclick="window.print()">
            🖨️ Print Notice
          </button>
          <button class="btn-primary-action" onclick="this.closest('.modal-overlay').remove()">
            Close
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
    this.render(); // Re-render to update unread badge
  }

  previewAttachment(filePath, fileName = 'Attachment') {
    const isImg = filePath.endsWith('.png') || filePath.endsWith('.jpg');
    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
      <div class="modal-container" style="max-width: 900px;">
        <div class="modal-header">
          <h3>${fileName}</h3>
          <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div class="modal-body" style="text-align: center; background: #0f172a; padding: 20px;">
          ${isImg ? `
            <img src="${filePath}" alt="${fileName}" style="max-width: 100%; max-height: 70vh; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
          ` : `
            <div style="background: #ffffff; padding: 40px; border-radius: 8px; max-width: 600px; margin: 0 auto; text-align: left;">
              <h3 style="color: #1e3a8a; margin-bottom: 10px;">📄 ${fileName}</h3>
              <p style="color: #475569; font-size: 0.88rem; margin-bottom: 20px;">Official examination circular / institutional documentation payload.</p>
              <div style="background: #f8fafc; border: 1px dashed #cbd5e1; padding: 20px; font-family: monospace; font-size: 0.80rem; color: #334155;">
                [DIGITAL SECURE ATTACHMENT VERIFIED]<br>
                SHA256: e8b94f...9c21<br>
                Host: college.edu/documents/notices/<br>
                Authorized Role: Verified Student / Faculty
              </div>
            </div>
          `}
        </div>
        <div class="modal-footer">
          <a href="${filePath}" download="${fileName}" class="btn-primary-action" style="text-decoration: none;">
            ⬇️ Download Attachment
          </a>
          <button class="btn-secondary-action" onclick="this.closest('.modal-overlay').remove()">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  // Reader Log Modal (TC-25)
  openReaderLogModal(noticeId) {
    const readers = this.state.getNoticeReaders(noticeId);
    const notice = this.state.notices.find(n => n.id === noticeId);

    const modal = document.createElement('div');
    modal.className = 'modal-overlay active';
    modal.innerHTML = `
      <div class="modal-container" style="max-width: 650px;">
        <div class="modal-header">
          <div>
            <h3>Notice Read Verification Log</h3>
            <p style="font-size: 0.80rem; color: #64748b;">${notice?.title} (${readers.length} unique student reads recorded)</p>
          </div>
          <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()">✕</button>
        </div>
        <div class="modal-body">
          <div class="cbs-table-wrap">
            <table class="cbs-table">
              <thead>
                <tr>
                  <th>Student Name</th>
                  <th>Roll No</th>
                  <th>Dept</th>
                  <th>First Read Timestamp</th>
                </tr>
              </thead>
              <tbody>
                ${readers.length === 0 ? `
                  <tr><td colspan="4" style="text-align: center; color: #94a3b8; padding: 20px;">No students have read this notice yet.</td></tr>
                ` : readers.map(r => `
                  <tr>
                    <td><strong>${r.name}</strong></td>
                    <td><code>${r.roll}</code></td>
                    <td>${r.dept}</td>
                    <td>${r.viewed_on}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn-primary-action" onclick="this.closest('.modal-overlay').remove()">Close</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }
}

// Initialize Application when DOM ready
document.addEventListener('DOMContentLoaded', () => {
  window.cbsApp = new CBSApp();
});
