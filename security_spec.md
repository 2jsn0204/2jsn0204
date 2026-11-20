# Security Specification — 나의 AI 프롬프트 창고

## 1. Data Invariants
1. **Public Guest Read + Admin-Only Write**: Guests can browse, search, filter, read full prompts, and copy text without signing in. Only the designated verified Google admin (`2jsn0204@gmail.com` with `email_verified == true`) can create, update, or delete documents in `/prompts/{promptId}`.
2. **Email Verification Enforcement**: `isAdmin()` requires both `request.auth.token.email == '2jsn0204@gmail.com'` and `request.auth.token.email_verified == true` to prevent unverified email spoofing.
3. **Strict Schema Enforcement**: Every document in `/prompts/{promptId}` must contain exactly `title`, `category`, `content`, and `createdAt` (no extra/shadow fields).
4. **Volumetric & Type Bounds**:
   - `promptId`: string matching `^[a-zA-Z0-9_\-]+$`, length `1..128`.
   - `title`: string, length `1..200`.
   - `category`: string strictly within `['사진 합성', '스타일 변환', '캐릭터·포스터']`.
   - `content`: string, length `1..20000`.
   - `createdAt`: Firestore `timestamp`, required to equal `request.time` on `create` and remain immutable on `update`.
5. **Default Deny**: All unmatched paths default to `allow read, write: if false;`.

## 2. Adversarial "Dirty Dozen" Payloads (Expected: PERMISSION_DENIED)
1. **Unauthenticated Write**: Guest attempts `create`, `update`, or `delete` on `/prompts/{promptId}` -> Rejected by `isAdmin()`.
2. **Non-Admin Authenticated Write**: Signed-in Google user with a different email attempts write -> Rejected by `request.auth.token.email == '2jsn0204@gmail.com'`.
3. **Unverified Admin Email Spoof**: Token has `email == '2jsn0204@gmail.com'` with `email_verified == false` -> Rejected by `email_verified == true`.
4. **Shadow Field Injection on Create**: Admin payload includes extra field `isFeatured: true` -> Rejected by `hasOnly`.
5. **Missing Required Field**: Missing `content` or `category` -> Rejected by `hasAll`.
6. **Invalid Category Enum**: `category: "기타"` -> Rejected by `isValidCategory`.
7. **Empty or Oversized Title**: `title` empty or `> 200` chars -> Rejected by `title.size()` check.
8. **Empty or Oversized Content**: `content` empty or `> 20000` chars -> Rejected by `content.size()` check.
9. **Client-Spoofed Timestamp on Create**: `createdAt` != `request.time` -> Rejected.
10. **Immutable `createdAt` Tampering on Update**: Updating `createdAt` -> Rejected by `affectedKeys().hasOnly(['title', 'category', 'content'])` and `incoming().createdAt == existing().createdAt`.
11. **ID Poisoning**: Document ID with spaces/symbols or `> 128` chars -> Rejected by `isValidId(promptId)`.
12. **Unfiltered List Query / Arbitrary Collection Write**: Unconstrained `collection(db, 'prompts')` or write to `/admins/fake` -> Rejected by `allow list` / catch-all deny.
