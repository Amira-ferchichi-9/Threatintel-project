import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  scenarios: {
    load_test: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
  },
  thresholds: {
    http_req_duration: ['p(99)<5000'],
    http_req_failed: ['rate<0.01'],
  },
};

const BASE_URL = 'http://localhost:8000';

const phishingEmail = JSON.stringify({
  subject: "Urgent: Verify your account",
  body: "Click here to verify: http://evil-phish.com/login",
  sender: "security@paypa1.com",
  headers: {}
});

const safeEmail = JSON.stringify({
  subject: "Meeting tomorrow",
  body: "Hi, just confirming our meeting tomorrow at 10am.",
  sender: "colleague@company.com",
  headers: {}
});

export default function () {
  const isHit = Math.random() < 0.6;

  if (isHit) {
    // 60% cache hit - même email
    const res = http.post(`${BASE_URL}/analyze`, safeEmail, {
      headers: { 'Content-Type': 'application/json' },
    });
    check(res, { 'cache hit 2xx': (r) => r.status >= 200 && r.status < 300 });
  } else {
    // 40% cache miss - email unique
    const uniqueEmail = JSON.stringify({
      subject: `Alert ${Math.random()}`,
      body: `Click http://malicious-${Math.random()}.com`,
      sender: `attacker${Math.random()}@evil.com`,
      headers: {}
    });
    const res = http.post(`${BASE_URL}/analyze`, uniqueEmail, {
      headers: { 'Content-Type': 'application/json' },
    });
    check(res, { 'cache miss 2xx': (r) => r.status >= 200 && r.status < 300 });
  }

  sleep(0);
}