# Security Specification — IIS Institute Management System

## 1. Data Invariants & Master Sources of Truth

1. **Zero Public Access**: Every collection defaults to `allow read, write: if false;`. No unauthenticated reads or writes are permitted anywhere.
2. **Email Verification & Role Bootstrapping**:
   - All writes and deletes require `request.auth != null && request.auth.token.email_verified == true`.
   - Bootstrapped Owner Admin: `request.auth.token.email == 'tanishq.me.me.me@gmail.com' && request.auth.token.email_verified == true`.
   - Non-owner users registering `/users/{userId}` can ONLY create their own profile (`userId == request.auth.uid`) with `role == 'TEACHER'` (least privilege) and CANNOT self-assign `'ADMIN'` or `'ACCOUNTANT'`.
   - Users are strictly forbidden from modifying `role` or `status` on their own `/users/{userId}` document (`isAdmin()` required for RBAC elevation).
3. **PII Isolation**:
   - `/users/{userId}` contains `email` and is readable strictly by `userId == request.auth.uid || isAdmin()`. Blanket `isSignedIn()` reads are forbidden.
   - `/students/{studentId}` contains guardian contact details and is readable strictly by `isAdmin() || isAccountant() || resource.data.assignedTeacherUid == request.auth.uid`.
4. **Least-Privilege Role Boundaries for Full Edit & Delete Support**:
   - **Teachers**:
     - CANNOT read, edit, or delete `/invoices`, `/payments`, `/expenses`, `/courses`, `/users`, or `/audit_logs`.
     - Can `get` and `list` ONLY `/students`, `/enrollments`, `/batches`, and `/student_reports` where `resource.data.assignedTeacherUid == request.auth.uid` (or `teacherUid == request.auth.uid`).
     - Can `create`, `update`, and `delete` ONLY their own `/student_reports/{reportId}` (`existing().teacherUid == request.auth.uid`).
   - **Accountants (`isAccountant()`)**:
     - Can `create`, `update`, and `delete` permitted financial records (`/invoices`, `/payments`, `/teacher_share_allocations`, `/teacher_payouts`, `/expenses`), while strictly prohibited from modifying RBAC `/users` or deleting master institute catalog records (`/courses`, `/batches`, `/teachers`, `/students`, `/audit_logs`).
   - **Administrators (`isAdmin()`)**:
     - Full authorized `create`, `update`, and `delete` across all institute records (`/courses`, `/batches`, `/teachers`, `/teacher_agreements`, `/teacher_share_allocations`, `/teacher_payouts`, `/students`, `/enrollments`, `/invoices`, `/payments`, `/expenses`, `/student_reports`, `/institute_settings`, `/audit_logs`, and non-self `/users`).
5. **Relational & Mathematical Integrity**:
   - Invoice `status == 'PAID'` strictly requires `netAmountDuePaise >= 0 && paidAmountPaise >= netAmountDuePaise && balanceDuePaise == 0` on both `create` and `update`.
   - Never reference `incoming()` or `request.resource` inside `allow read` or `allow delete` blocks.
   - Zero `get()`/`exists()` calls inside `allow list` blocks.
6. **Temporal & Key Integrity**:
   - `createdAt == request.time` on `create`; `createdAt == existing().createdAt` and `updatedAt == request.time` on `update` (for collections with `updatedAt`).
   - Strict `hasAll` and `hasOnly` key checks on every entity validation helper; action-based `affectedKeys().hasOnly(...)` on updates.

## 2. The "Dirty Dozen" Adversarial Payloads

1. **Privilege Escalation (Self-Admin Signup)**: Standard user `uid_attacker` creates `/users/uid_attacker` with `role: "ADMIN"`. -> `PERMISSION_DENIED`
2. **Email Spoofing (Unverified Admin Email)**: Token has `email: "tanishq.me.me.me@gmail.com"` with `email_verified: false` attempting admin write/delete. -> `PERMISSION_DENIED`
3. **Shadow Field Injection**: Valid student creation or update payload plus unauthorized `"isSuperVerified": true` ghost key. -> `PERMISSION_DENIED`
4. **PII Blanket Scraping**: Authenticated teacher `uid_teacher_b` attempts `get` on `/users/uid_teacher_a` or unassigned `/students/stu_1`. -> `PERMISSION_DENIED`
5. **Unauthorized Financial Snooping / Deletion by Teacher**: Authenticated teacher attempts `list`, `update`, or `delete` on `/invoices`, `/payments`, or `/expenses`. -> `PERMISSION_DENIED`
6. **Premature Paid Invoice Forgery**: Accountant creates or edits `/invoices/inv_1` with `status: "PAID"`, `netAmountDuePaise: 200000`, `paidAmountPaise: 50000`. -> `PERMISSION_DENIED`
7. **Unauthorized Role Deletion by Accountant**: Accountant attempts `delete` on `/users/usr_1` or `/teachers/tch_1`. -> `PERMISSION_DENIED`
8. **ID Poisoning / Resource Exhaustion**: Attacker creates or deletes `/students/bad$id!@#` or injects a 5,000-character `fullName`. -> `PERMISSION_DENIED`
9. **Cross-Teacher Report Tampering / Deletion**: Teacher B attempts `update` or `delete` on `/student_reports/rep_1` owned by Teacher A (`teacherUid == 'uid_teacher_a'`). -> `PERMISSION_DENIED`
10. **Immutable Field Tampering**: Updating `createdAt` or `createdBy` or `idempotencyKey` on `/payments/pay_1`. -> `PERMISSION_DENIED`
11. **Client Timestamp Forgery**: Creating a payment with a forged past `createdAt` timestamp instead of `request.time`. -> `PERMISSION_DENIED`
12. **Self-Lockout Admin Deletion**: Admin attempts `delete` on their own active `/users/$(request.auth.uid)` profile. -> `PERMISSION_DENIED`
