import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE || '/api';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 60000,
});

export async function uploadLogs(file, logType = 'auto') {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('log_type', logType);
  const { data } = await api.post('/upload-logs', formData);
  return data;
}

export async function extractLocalChannel(channelId) {
  const formData = new FormData();
  formData.append('source_id', channelId);
  formData.append('log_type', 'auto');
  const { data } = await api.post('/upload-logs', formData);
  return data;
}

export async function analyzeLiveStream(events) {
  const { data } = await api.post('/analyze-live-stream', { events });
  return data;
}

export async function getEvents(sessionId, suspiciousOnly = false) {
  const { data } = await api.get('/events', {
    params: { session_id: sessionId, suspicious_only: suspiciousOnly },
  });
  return data;
}

export async function getTimeline(sessionId) {
  const { data } = await api.get('/timeline', {
    params: { session_id: sessionId },
  });
  return data;
}

export async function getGraph(sessionId, recalculate = false, sample = false) {
  const { data } = await api.get('/graph', {
    params: { session_id: sessionId, recalculate, sample },
  });
  return data;
}

export async function getAnalysis(sessionId) {
  const { data } = await api.get('/analysis', {
    params: { session_id: sessionId },
  });
  return data;
}

export async function getReplay(sessionId) {
  const { data } = await api.get('/replay', {
    params: { session_id: sessionId },
  });
  return data;
}

export async function getLocalLogChannels() {
  const { data } = await api.get('/extract-local-logs');
  return data;
}

export async function explainEvent(event, useAi = false) {
  const { data } = await api.post('/explain-event', { event, use_ai: useAi });
  return data;
}

export default api;
