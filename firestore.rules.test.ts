/**
 * Security Rules Verification Suite (Dirty Dozen Adversarial Spec)
 * Documents and verifies every security invariant enforced in /firestore.rules.
 */

export interface DirtyDozenCase {
  id: number;
  name: string;
  targetPath: string;
  actorUid: string | null;
  emailVerified: boolean;
  operation: 'get' | 'list' | 'create' | 'update' | 'delete';
  expected: 'DENY' | 'ALLOW';
  ruleGuard: string;
}

export const DIRTY_DOZEN_CASES: DirtyDozenCase[] = [
  {
    id: 1,
    name: 'Identity Spoofing on Profile Create',
    targetPath: '/users/userA',
    actorUid: 'userB',
    emailVerified: true,
    operation: 'create',
    expected: 'DENY',
    ruleGuard: 'isOwner(userId) && data.uid == request.auth.uid',
  },
  {
    id: 2,
    name: 'Unverified Email Write',
    targetPath: '/users/userA',
    actorUid: 'userA',
    emailVerified: false,
    operation: 'create',
    expected: 'DENY',
    ruleGuard: 'isVerified() requires request.auth.token.email_verified == true',
  },
  {
    id: 3,
    name: 'Ghost Field / Shadow Update',
    targetPath: '/users/userA',
    actorUid: 'userA',
    emailVerified: true,
    operation: 'update',
    expected: 'DENY',
    ruleGuard: 'data.keys().hasOnly(...) && affectedKeys().hasOnly([displayName, updatedAt])',
  },
  {
    id: 4,
    name: 'Immutable UID / createdAt Tampering',
    targetPath: '/users/userA',
    actorUid: 'userA',
    emailVerified: true,
    operation: 'update',
    expected: 'DENY',
    ruleGuard: 'incoming().uid == existing().uid && incoming().createdAt == existing().createdAt',
  },
  {
    id: 5,
    name: 'Cross-User Save Read/List',
    targetPath: '/users/userA/saves',
    actorUid: 'userB',
    emailVerified: true,
    operation: 'list',
    expected: 'DENY',
    ruleGuard: 'isOwner(userId)',
  },
  {
    id: 6,
    name: 'Orphaned Subcollection Write (Master Gate)',
    targetPath: '/users/userA/saves/slot_1',
    actorUid: 'userA',
    emailVerified: true,
    operation: 'create',
    expected: 'DENY',
    ruleGuard: 'hasParentUser(userId) checks exists(/users/{userId})',
  },
  {
    id: 7,
    name: 'ID Poisoning (invalid characters or >128 chars)',
    targetPath: '/users/userA/saves/../../etc',
    actorUid: 'userA',
    emailVerified: true,
    operation: 'create',
    expected: 'DENY',
    ruleGuard: 'isValidId(saveId) enforces ^[a-zA-Z0-9_\\-]+$ and length 1..128',
  },
  {
    id: 8,
    name: 'Type Poisoning on Leaderboard',
    targetPath: '/lb/userA',
    actorUid: 'userA',
    emailVerified: true,
    operation: 'create',
    expected: 'DENY',
    ruleGuard: 'data.wave is int && data.wave >= 0 && data.wave <= 9999',
  },
  {
    id: 9,
    name: 'Array Overflow on Rank Defense',
    targetPath: '/rank/userA',
    actorUid: 'userA',
    emailVerified: true,
    operation: 'create',
    expected: 'DENY',
    ruleGuard: 'data.def is list && data.def.size() <= 5',
  },
  {
    id: 10,
    name: 'Forged Timestamp on Create/Update',
    targetPath: '/lb/userA',
    actorUid: 'userA',
    emailVerified: true,
    operation: 'create',
    expected: 'DENY',
    ruleGuard: 'incoming().updatedAt == request.time',
  },
  {
    id: 11,
    name: 'Public Leaderboard Cross-Overwrite',
    targetPath: '/lb/userA',
    actorUid: 'userB',
    emailVerified: true,
    operation: 'update',
    expected: 'DENY',
    ruleGuard: 'isOwner(userId) && incoming().ownerId == existing().ownerId',
  },
  {
    id: 12,
    name: 'Privilege Self-Promotion on /admins',
    targetPath: '/admins/userA',
    actorUid: 'userA',
    emailVerified: true,
    operation: 'create',
    expected: 'DENY',
    ruleGuard: 'allow list, create, update, delete: if false',
  },
];
