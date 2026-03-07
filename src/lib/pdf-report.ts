// Client-side PDF generation using jsPDF + jspdf-autotable (loaded via CDN)
// This file is included as an inline <script> in site-report.astro

declare const jspdf: any;

interface ReportData {
  domain: string;
  timestamp: string;
  overallScore: { total: number; grade: { score: number; grade: string; color: string } };
  emailSecurity: any | null;
  securityHeaders: any | null;
  dns: any | null;
  certificates: any | null;
  errors: string[];
}

export function generatePDF(data: ReportData) {
  const { jsPDF } = jspdf;
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 20;
  const contentWidth = pageWidth - margin * 2;
  const date = new Date(data.timestamp).toLocaleDateString('es-AR', {
    year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });

  function addFooter(pageNum: number) {
    doc.setFontSize(8);
    doc.setTextColor(150);
    doc.text(`Generado por tools.delzo.cloud — ${date}`, margin, pageHeight - 10);
    doc.text(`Página ${pageNum}`, pageWidth - margin, pageHeight - 10, { align: 'right' });
  }

  function gradeColor(color: string): [number, number, number] {
    if (color === 'green') return [16, 185, 129];
    if (color === 'yellow') return [245, 158, 11];
    return [239, 68, 68];
  }

  // ═══════════════════════════════════════════
  // PAGE 1 — Cover + Summary
  // ═══════════════════════════════════════════
  let y = 40;

  // Wordmark
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 30, 30);
  doc.text('delzo', margin, y);
  const delzoWidth = doc.getTextWidth('delzo');
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(16, 185, 129);
  doc.text('.cloud', margin + delzoWidth, y);

  // Title
  y += 20;
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 30, 30);
  doc.text(`Reporte de Seguridad`, margin, y);
  y += 9;
  doc.setFontSize(14);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100);
  doc.text(data.domain, margin, y);

  y += 8;
  doc.setFontSize(10);
  doc.setTextColor(150);
  doc.text(`Generado: ${date}`, margin, y);

  // Overall Score Badge
  y += 20;
  const badgeColor = gradeColor(data.overallScore.grade.color);
  doc.setFillColor(...badgeColor);
  doc.roundedRect(margin, y, 50, 40, 4, 4, 'F');
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(255, 255, 255);
  doc.text(data.overallScore.grade.grade, margin + 25, y + 20, { align: 'center' });
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.text(`${data.overallScore.total}/100`, margin + 25, y + 32, { align: 'center' });

  // Score label
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 30, 30);
  doc.text('Score General', margin + 60, y + 15);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100);
  doc.text('Promedio ponderado de Email Security + Security Headers', margin + 60, y + 25);

  // Summary table
  y += 55;
  const summaryRows: any[] = [];

  if (data.emailSecurity) {
    summaryRows.push(['Email Security', `${data.emailSecurity.score.total}/100`, data.emailSecurity.score.grade.grade]);
  } else {
    summaryRows.push(['Email Security', 'Error', '—']);
  }

  if (data.securityHeaders) {
    summaryRows.push(['Security Headers', `${data.securityHeaders.score.total}/100`, data.securityHeaders.score.grade.grade]);
  } else {
    summaryRows.push(['Security Headers', 'Error', '—']);
  }

  summaryRows.push(['DNS Records', 'Informativo', '—']);
  summaryRows.push(['Certificados SSL/TLS', 'Informativo', '—']);

  (doc as any).autoTable({
    startY: y,
    head: [['Sección', 'Score', 'Grade']],
    body: summaryRows,
    margin: { left: margin, right: margin },
    headStyles: { fillColor: [30, 30, 30], fontSize: 10 },
    bodyStyles: { fontSize: 10 },
    columnStyles: {
      0: { cellWidth: contentWidth * 0.5 },
      1: { cellWidth: contentWidth * 0.3, halign: 'center' },
      2: { cellWidth: contentWidth * 0.2, halign: 'center' },
    },
  });

  // Errors section
  if (data.errors.length > 0) {
    const tableEndY = (doc as any).lastAutoTable.finalY + 15;
    doc.setFontSize(10);
    doc.setTextColor(239, 68, 68);
    doc.text('Errores durante el análisis:', margin, tableEndY);
    doc.setTextColor(100);
    data.errors.forEach((err: string, i: number) => {
      doc.text(`• ${err}`, margin + 5, tableEndY + 8 + i * 6);
    });
  }

  addFooter(1);

  // ═══════════════════════════════════════════
  // PAGE 2 — Email Security
  // ═══════════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 30, 30);
  doc.text('Email Security', margin, y);

  if (data.emailSecurity) {
    const es = data.emailSecurity;
    y += 8;
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    const esBadgeColor = gradeColor(es.score.grade.color);
    doc.setTextColor(...esBadgeColor);
    doc.text(`Score: ${es.score.total}/100 (${es.score.grade.grade})`, margin, y);

    y += 10;
    const emailRows = [
      ['SPF', es.spf.status.toUpperCase(), `${es.score.spfScore}/30`, es.spf.details, es.spf.recommendation],
      ['DMARC', es.dmarc.status.toUpperCase(), `${es.score.dmarcScore}/40`, es.dmarc.details, es.dmarc.recommendation],
      ['DKIM', es.dkim.status.toUpperCase(), `${es.score.dkimScore}/30`, es.dkim.details, es.dkim.recommendation],
    ];

    (doc as any).autoTable({
      startY: y,
      head: [['Protocolo', 'Status', 'Score', 'Detalle', 'Recomendación']],
      body: emailRows,
      margin: { left: margin, right: margin },
      headStyles: { fillColor: [30, 30, 30], fontSize: 9 },
      bodyStyles: { fontSize: 8 },
      columnStyles: {
        0: { cellWidth: 22 },
        1: { cellWidth: 18, halign: 'center' },
        2: { cellWidth: 18, halign: 'center' },
        3: { cellWidth: 55 },
        4: { cellWidth: 55 },
      },
      didParseCell: (hookData: any) => {
        if (hookData.section === 'body' && hookData.column.index === 1) {
          const val = hookData.cell.raw;
          if (val === 'PASS') hookData.cell.styles.textColor = [16, 185, 129];
          else if (val === 'WARNING') hookData.cell.styles.textColor = [245, 158, 11];
          else if (val === 'FAIL') hookData.cell.styles.textColor = [239, 68, 68];
        }
      },
    });

    // Records found
    const recordsY = (doc as any).lastAutoTable.finalY + 12;
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 30, 30);
    doc.text('Registros encontrados', margin, recordsY);

    const recordRows: any[] = [];
    if (es.spf.record) recordRows.push(['SPF', es.spf.record]);
    if (es.dmarc.record) recordRows.push(['DMARC', es.dmarc.record]);
    if (es.dkim.record) recordRows.push([`DKIM (${es.dkim.selector})`, es.dkim.record]);

    if (recordRows.length > 0) {
      (doc as any).autoTable({
        startY: recordsY + 5,
        head: [['Tipo', 'Registro']],
        body: recordRows,
        margin: { left: margin, right: margin },
        headStyles: { fillColor: [30, 30, 30], fontSize: 9 },
        bodyStyles: { fontSize: 7, font: 'courier' },
        columnStyles: {
          0: { cellWidth: 30, font: 'helvetica' },
          1: { cellWidth: contentWidth - 30 },
        },
      });
    }
  } else {
    y += 10;
    doc.setFontSize(10);
    doc.setTextColor(239, 68, 68);
    doc.text('No se pudo analizar la seguridad de email para este dominio.', margin, y);
  }

  addFooter(2);

  // ═══════════════════════════════════════════
  // PAGE 3 — Security Headers
  // ═══════════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 30, 30);
  doc.text('Security Headers', margin, y);

  if (data.securityHeaders) {
    const sh = data.securityHeaders;
    y += 8;
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    const shBadgeColor = gradeColor(sh.score.grade.color);
    doc.setTextColor(...shBadgeColor);
    doc.text(`Score: ${sh.score.total}/100 (${sh.score.grade.grade})`, margin, y);

    y += 10;
    const headerRows = sh.headers.map((h: any) => {
      const statusLabel = h.status === 'pass' ? 'PASS' : h.status === 'warning' ? 'WARNING' : 'FAIL';
      return [h.name, statusLabel, h.value || '—', `${h.score}/${h.weight}`];
    });

    (doc as any).autoTable({
      startY: y,
      head: [['Header', 'Status', 'Valor', 'Score']],
      body: headerRows,
      margin: { left: margin, right: margin },
      headStyles: { fillColor: [30, 30, 30], fontSize: 9 },
      bodyStyles: { fontSize: 8 },
      columnStyles: {
        0: { cellWidth: 45 },
        1: { cellWidth: 22, halign: 'center' },
        2: { cellWidth: 80 },
        3: { cellWidth: 20, halign: 'center' },
      },
      didParseCell: (hookData: any) => {
        if (hookData.section === 'body' && hookData.column.index === 1) {
          const val = hookData.cell.raw;
          if (val === 'PASS') hookData.cell.styles.textColor = [16, 185, 129];
          else if (val === 'WARNING') hookData.cell.styles.textColor = [245, 158, 11];
          else if (val === 'FAIL') hookData.cell.styles.textColor = [239, 68, 68];
        }
      },
    });
  } else {
    y += 10;
    doc.setFontSize(10);
    doc.setTextColor(239, 68, 68);
    doc.text('No se pudieron verificar los headers de seguridad para este dominio.', margin, y);
  }

  addFooter(3);

  // ═══════════════════════════════════════════
  // PAGE 4 — DNS Records
  // ═══════════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 30, 30);
  doc.text('DNS Records', margin, y);

  y += 5;
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100);
  doc.text('Sección informativa — no afecta el score general.', margin, y);

  if (data.dns) {
    const dnsTypes = [
      { label: 'A', records: data.dns.a },
      { label: 'MX', records: data.dns.mx },
      { label: 'NS', records: data.dns.ns },
      { label: 'TXT', records: data.dns.txt },
    ];

    const allRows: any[] = [];
    for (const dt of dnsTypes) {
      if (dt.records && dt.records.length > 0) {
        for (const r of dt.records) {
          allRows.push([dt.label, r.data, String(r.TTL)]);
        }
      } else {
        allRows.push([dt.label, 'Sin registros', '—']);
      }
    }

    y += 8;
    (doc as any).autoTable({
      startY: y,
      head: [['Tipo', 'Valor', 'TTL']],
      body: allRows,
      margin: { left: margin, right: margin },
      headStyles: { fillColor: [30, 30, 30], fontSize: 9 },
      bodyStyles: { fontSize: 8 },
      columnStyles: {
        0: { cellWidth: 20 },
        1: { cellWidth: contentWidth - 40 },
        2: { cellWidth: 20, halign: 'center' },
      },
    });
  } else {
    y += 15;
    doc.setTextColor(239, 68, 68);
    doc.text('No se pudieron consultar los registros DNS.', margin, y);
  }

  addFooter(4);

  // ═══════════════════════════════════════════
  // PAGE 5 — Certificates
  // ═══════════════════════════════════════════
  doc.addPage();
  y = 25;

  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 30, 30);
  doc.text('Certificados SSL/TLS', margin, y);

  y += 5;
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100);
  doc.text('Sección informativa — datos de Certificate Transparency (crt.sh).', margin, y);

  if (data.certificates && data.certificates.certs.length > 0) {
    const certs = data.certificates.certs;
    const valid = certs.filter((c: any) => c.status === 'valid').length;
    const expiring = certs.filter((c: any) => c.status === 'expiring').length;
    const expired = certs.filter((c: any) => c.status === 'expired').length;

    y += 8;
    doc.setTextColor(30, 30, 30);
    doc.text(`Total: ${certs.length} certificados — ${valid} válidos, ${expiring} por vencer, ${expired} expirados`, margin, y);

    y += 8;
    // Show up to 20 most recent certs
    const certRows = certs.slice(0, 20).map((c: any) => {
      const notBefore = new Date(c.notBefore).toLocaleDateString('es-AR');
      const notAfter = new Date(c.notAfter).toLocaleDateString('es-AR');
      const statusLabel = c.status === 'valid' ? 'Válido' : c.status === 'expiring' ? 'Por vencer' : 'Expirado';
      // Extract short issuer (CN or O)
      const issuerMatch = c.issuer.match(/(?:CN|O)=([^,]+)/);
      const issuerShort = issuerMatch ? issuerMatch[1] : c.issuer.substring(0, 30);
      return [c.commonName, issuerShort, notBefore, notAfter, statusLabel];
    });

    (doc as any).autoTable({
      startY: y,
      head: [['Common Name', 'Emisor', 'Desde', 'Hasta', 'Status']],
      body: certRows,
      margin: { left: margin, right: margin },
      headStyles: { fillColor: [30, 30, 30], fontSize: 9 },
      bodyStyles: { fontSize: 7 },
      columnStyles: {
        0: { cellWidth: 40 },
        1: { cellWidth: 40 },
        2: { cellWidth: 25, halign: 'center' },
        3: { cellWidth: 25, halign: 'center' },
        4: { cellWidth: 22, halign: 'center' },
      },
      didParseCell: (hookData: any) => {
        if (hookData.section === 'body' && hookData.column.index === 4) {
          const val = hookData.cell.raw;
          if (val === 'Válido') hookData.cell.styles.textColor = [16, 185, 129];
          else if (val === 'Por vencer') hookData.cell.styles.textColor = [245, 158, 11];
          else if (val === 'Expirado') hookData.cell.styles.textColor = [239, 68, 68];
        }
      },
    });
  } else if (data.certificates) {
    y += 15;
    doc.setTextColor(100);
    doc.text('No se encontraron certificados para este dominio.', margin, y);
  } else {
    y += 15;
    doc.setTextColor(239, 68, 68);
    doc.text('No se pudieron consultar los certificados.', margin, y);
  }

  addFooter(5);

  // Save
  doc.save(`reporte-seguridad-${data.domain}.pdf`);
}
