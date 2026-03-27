/**
 * Yile API Utilities
 * Date formatting, validators, and response normalizers
 */

export function formatYileDate(date, isEndOfDay = false) {
  const d = date instanceof Date ? date : new Date(date);
  const pad = n => n.toString().padStart(2, '0');
  const time = isEndOfDay ? '23:59:59' : '00:00:00';
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`;
}

export function validateDateRange(startDate, endDate) {
  const start = new Date(startDate);
  const end = new Date(endDate);
  
  if (start.getFullYear() !== end.getFullYear() || start.getMonth() !== end.getMonth()) {
    throw new Error('Yile API requires start and end dates to be in the same month');
  }
  
  if (start > end) {
    throw new Error('Start date must be before end date');
  }
  
  return true;
}

export function getSameMonthRange(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  const firstOfMonth = new Date(d.getFullYear(), d.getMonth(), 1);
  const lastOfMonth = new Date(d.getFullYear(), d.getMonth() + 1, 0);
  
  return {
    startTime: formatYileDate(firstOfMonth),
    endTime: formatYileDate(lastOfMonth, true)
  };
}

export function normalizeResponse(yileResponse) {
  if (!yileResponse) {
    return { success: false, data: null, error: 'No response received' };
  }

  const code = String(yileResponse.code);
  
  if (code === '0') {
    return {
      success: false,
      data: null,
      error: yileResponse.msg || yileResponse.message || 'Business error'
    };
  }
  
  if (code === '9') {
    return {
      success: false,
      data: null,
      error: 'Token expired or invalid',
      tokenError: true
    };
  }
  
  if (code === '1') {
    const data = yileResponse.msg || yileResponse.data;
    return {
      success: true,
      data,
      rows: data?.rows || [],
      total: data?.total || 0,
      currPage: data?.currPage || 1,
      pageSize: data?.pageSize || 15
    };
  }
  
  return {
    success: false,
    data: yileResponse,
    error: `Unknown response code: ${code}`
  };
}

export function extractRows(yileResponse) {
  const normalized = normalizeResponse(yileResponse);
  return normalized.rows || [];
}

export function isSuccess(yileResponse) {
  return String(yileResponse?.code) === '1';
}

export function validateDeviceId(deviceId) {
  if (!deviceId || typeof deviceId !== 'string') {
    throw new Error('Device ID is required and must be a string');
  }
  return deviceId.replace(/\D/g, '').padStart(11, '0');
}

export function parseCommaSeparated(value) {
  if (Array.isArray(value)) {
    return value.join(',');
  }
  return String(value);
}
