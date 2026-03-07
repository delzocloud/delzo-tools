export interface GradeResult {
  score: number;
  grade: string;
  color: 'green' | 'yellow' | 'red';
}

export function computeGrade(score: number): GradeResult {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));

  let grade: string;
  let color: 'green' | 'yellow' | 'red';

  if (clamped >= 95) {
    grade = 'A+'; color = 'green';
  } else if (clamped >= 85) {
    grade = 'A'; color = 'green';
  } else if (clamped >= 75) {
    grade = 'B'; color = 'green';
  } else if (clamped >= 60) {
    grade = 'C'; color = 'yellow';
  } else if (clamped >= 40) {
    grade = 'D'; color = 'yellow';
  } else {
    grade = 'F'; color = 'red';
  }

  return { score: clamped, grade, color };
}
