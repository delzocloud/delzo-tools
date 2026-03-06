import type { AuthStatus, SpfResult, DmarcResult, DkimResult } from './types';
import { queryDns } from './dns-client';

export async function analyzeSpf(domain: string): Promise<SpfResult> {
  try {
    const data = await queryDns(domain, 'TXT');
    const spfRecord = (data.Answer || [])
      .map(r => r.data.replace(/^"|"$/g, ''))
      .find(d => d.startsWith('v=spf1'));

    if (!spfRecord) {
      return {
        status: 'fail',
        record: null,
        details: 'No se encontró registro SPF.',
        recommendation: 'Agregá un registro TXT con la política SPF. Ejemplo: v=spf1 include:_spf.google.com ~all',
      };
    }

    let status: AuthStatus = 'pass';
    let details = 'Registro SPF encontrado.';
    let recommendation = 'Tu registro SPF está configurado correctamente.';

    if (spfRecord.includes('+all')) {
      status = 'fail';
      details = 'El registro SPF permite que cualquier servidor envíe emails (+all).';
      recommendation = 'Cambiá "+all" por "~all" o "-all" para restringir el envío.';
    } else if (spfRecord.includes('?all')) {
      status = 'warning';
      details = 'El registro SPF usa "?all" (neutral), no protege contra spoofing.';
      recommendation = 'Cambiá "?all" por "~all" o "-all" para mayor protección.';
    } else if (spfRecord.includes('~all')) {
      details = 'Registro SPF con soft fail (~all). Buena configuración.';
    } else if (spfRecord.includes('-all')) {
      details = 'Registro SPF con hard fail (-all). Configuración estricta.';
    }

    const lookups = (spfRecord.match(/\b(include:|a:|a\b|mx:|mx\b|ptr:|ptr\b|exists:|redirect=)/g) || []).length;
    if (lookups > 10) {
      status = 'warning';
      details += ` Atención: ~${lookups} lookups DNS (máximo permitido: 10).`;
      recommendation = 'Reducí la cantidad de mecanismos DNS (include, a, mx, ptr, exists, redirect) para no exceder el límite de 10 lookups.';
    }

    return { status, record: spfRecord, details, recommendation };
  } catch {
    return {
      status: 'fail',
      record: null,
      details: 'Error al consultar el registro SPF.',
      recommendation: 'Verificá que el dominio sea correcto y tenga registros DNS configurados.',
    };
  }
}

export async function analyzeDmarc(domain: string): Promise<DmarcResult> {
  try {
    const data = await queryDns(`_dmarc.${domain}`, 'TXT');
    const dmarcRecord = (data.Answer || [])
      .map(r => r.data.replace(/^"|"$/g, ''))
      .find(d => d.startsWith('v=DMARC1'));

    if (!dmarcRecord) {
      return {
        status: 'fail',
        record: null,
        policy: null,
        details: 'No se encontró registro DMARC.',
        recommendation: 'Agregá un registro TXT en _dmarc.tudominio.com. Ejemplo: v=DMARC1; p=quarantine; rua=mailto:dmarc@tudominio.com',
      };
    }

    const policyMatch = dmarcRecord.match(/;\s*p=(\w+)/);
    const policy = policyMatch ? policyMatch[1] : null;

    let status: AuthStatus = 'pass';
    let details = `Registro DMARC encontrado. Política: ${policy || 'no definida'}.`;
    let recommendation = 'Tu registro DMARC está configurado correctamente.';

    if (policy === 'none') {
      status = 'warning';
      details = 'DMARC está en modo "none" (solo monitoreo, no bloquea nada).';
      recommendation = 'Considerá cambiar la política a "quarantine" o "reject" una vez que verifiques que tus emails legítimos pasen los checks.';
    } else if (!policy) {
      status = 'fail';
      details = 'El registro DMARC no tiene política definida.';
      recommendation = 'Agregá p=quarantine o p=reject al registro DMARC.';
    }

    if (!dmarcRecord.includes('rua=')) {
      if (status === 'pass') status = 'warning';
      recommendation += ' Agregá rua=mailto:... para recibir reportes de autenticación.';
    }

    return { status, record: dmarcRecord, policy, details, recommendation };
  } catch {
    return {
      status: 'fail',
      record: null,
      policy: null,
      details: 'Error al consultar el registro DMARC.',
      recommendation: 'Verificá que el dominio sea correcto.',
    };
  }
}

export async function analyzeDkim(domain: string): Promise<DkimResult> {
  const selectors = ['google', 'default', 'selector1', 'selector2', 'dkim', 'mail', 'k1'];

  const results = await Promise.allSettled(
    selectors.map(async (selector) => {
      const data = await queryDns(`${selector}._domainkey.${domain}`, 'TXT');
      const dkimRecord = (data.Answer || [])
        .map(r => r.data.replace(/^"|"$/g, ''))
        .find(d => d.includes('v=DKIM1') || d.includes('p='));
      return { selector, record: dkimRecord };
    })
  );

  for (const result of results) {
    if (result.status === 'fulfilled' && result.value.record) {
      return {
        status: 'pass' as const,
        record: result.value.record,
        selector: result.value.selector,
        details: `Registro DKIM encontrado con selector "${result.value.selector}".`,
        recommendation: 'Tu DKIM está configurado correctamente.',
      };
    }
  }

  return {
    status: 'warning',
    record: null,
    selector: '',
    details: 'No se encontró DKIM en los selectores comunes (google, default, selector1, selector2, dkim, mail, k1).',
    recommendation: 'Si usás DKIM, verificá el selector correcto con tu proveedor de email. Si no lo tenés configurado, activalo desde tu proveedor.',
  };
}
