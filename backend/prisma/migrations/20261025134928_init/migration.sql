-- CreateEnum
CREATE TYPE "Role" AS ENUM ('ADMIN', 'ANALYST', 'DECISION_MAKER');

-- CreateEnum
CREATE TYPE "Exposure" AS ENUM ('PUBLIC', 'INTERNAL', 'RESTRICTED');

-- CreateEnum
CREATE TYPE "Sensitivity" AS ENUM ('LOW', 'MEDIUM', 'HIGH');

-- CreateEnum
CREATE TYPE "Priority" AS ENUM ('P1', 'P2', 'P3', 'P4');

-- CreateEnum
CREATE TYPE "ModelKind" AS ENUM ('M1', 'M2');

-- CreateEnum
CREATE TYPE "CorrectionStatus" AS ENUM ('IMPORTED', 'VALIDATED', 'PRIORITIZED', 'ASSIGNED', 'IN_REMEDIATION', 'REMEDIATED', 'VERIFIED', 'CLOSED', 'REJECTED');

-- CreateEnum
CREATE TYPE "AuditOutcome" AS ENUM ('SUCCESS', 'DENIED', 'FAILURE');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "mustChangePassword" BOOLEAN NOT NULL DEFAULT true,
    "failedLogins" INTEGER NOT NULL DEFAULT 0,
    "lockedUntil" TIMESTAMP(3),
    "tokenVersion" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RefreshToken" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "familyId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RefreshToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Application" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "exposure" "Exposure" NOT NULL,
    "sensitivity" "Sensitivity" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Application_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "tool" TEXT NOT NULL DEFAULT 'ZAP',
    "fileName" TEXT NOT NULL,
    "fileSha256" TEXT NOT NULL,
    "sizeBytes" INTEGER NOT NULL,
    "rawReport" JSONB,
    "findingsTotal" INTEGER NOT NULL DEFAULT 0,
    "findingsNew" INTEGER NOT NULL DEFAULT 0,
    "findingsUpdated" INTEGER NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL DEFAULT 'COMPLETED',
    "importedById" TEXT NOT NULL,
    "importedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "lastSeenScanId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" INTEGER NOT NULL,
    "confidence" TEXT,
    "cweId" INTEGER,
    "cveId" TEXT,
    "description" TEXT NOT NULL,
    "solution" TEXT,
    "instancesCount" INTEGER NOT NULL DEFAULT 1,
    "sampleUrls" JSONB,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "exploitProbability" DOUBLE PRECISION,
    "modelProbability" DOUBLE PRECISION,
    "modelPriority" "Priority",
    "expertPriority" "Priority",
    "effectivePriority" "Priority",

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Prediction" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "model" "ModelKind" NOT NULL,
    "version" TEXT NOT NULL,
    "simulated" BOOLEAN NOT NULL DEFAULT true,
    "provider" TEXT NOT NULL,
    "probability" DOUBLE PRECISION NOT NULL,
    "priority" "Priority",
    "explanation" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Prediction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Annotation" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "annotatorId" TEXT NOT NULL,
    "priority" "Priority" NOT NULL,
    "comment" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Annotation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Correction" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "status" "CorrectionStatus" NOT NULL DEFAULT 'IMPORTED',
    "assigneeId" TEXT,
    "dueDate" TIMESTAMP(3),
    "comment" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Correction_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT,
    "action" TEXT NOT NULL,
    "resourceType" TEXT,
    "resourceId" TEXT,
    "outcome" "AuditOutcome" NOT NULL,
    "ip" TEXT,
    "userAgent" TEXT,
    "requestId" TEXT,
    "metadata" JSONB,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "RefreshToken_tokenHash_key" ON "RefreshToken"("tokenHash");

-- CreateIndex
CREATE INDEX "RefreshToken_userId_idx" ON "RefreshToken"("userId");

-- CreateIndex
CREATE INDEX "RefreshToken_familyId_idx" ON "RefreshToken"("familyId");

-- CreateIndex
CREATE UNIQUE INDEX "Application_name_key" ON "Application"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Scan_applicationId_fileSha256_key" ON "Scan"("applicationId", "fileSha256");

-- CreateIndex
CREATE INDEX "Finding_applicationId_idx" ON "Finding"("applicationId");

-- CreateIndex
CREATE INDEX "Finding_effectivePriority_idx" ON "Finding"("effectivePriority");

-- CreateIndex
CREATE UNIQUE INDEX "Finding_applicationId_fingerprint_key" ON "Finding"("applicationId", "fingerprint");

-- CreateIndex
CREATE INDEX "Prediction_findingId_model_createdAt_idx" ON "Prediction"("findingId", "model", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "Correction_findingId_key" ON "Correction"("findingId");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");

-- CreateIndex
CREATE INDEX "AuditLog_userId_idx" ON "AuditLog"("userId");

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "Application"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_importedById_fkey" FOREIGN KEY ("importedById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "Application"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Prediction" ADD CONSTRAINT "Prediction_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Annotation" ADD CONSTRAINT "Annotation_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Annotation" ADD CONSTRAINT "Annotation_annotatorId_fkey" FOREIGN KEY ("annotatorId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Correction" ADD CONSTRAINT "Correction_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Correction" ADD CONSTRAINT "Correction_assigneeId_fkey" FOREIGN KEY ("assigneeId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
