# Loan Repayment Planner

A Node.js web application to plan and minimize home loan repayments.

## Loan Details (pre-configured)
- Sanctioned amount: ₹92,95,377
- Disbursed (Tranche 1): ₹80,55,994
- Remaining disbursement: ₹12,39,383
- EMI: ₹73,606
- Rate: 7.35% floating
- Maturity: 2041

## Features
- Split remaining ₹12,39,383 into two tranches (A & B) — set amount and month for each
- Lumpsum prepayments every 6 months (₹5L, ₹7.5L, or ₹10L)
- Floating rate simulation (slider from 6% to 10%)
- Live balance chart comparing with vs. without lumpsums
- Full repayment schedule table with color-coded rows
- Export schedule to CSV
- Print-ready

## Requirements
- Node.js v14 or higher (no npm packages required)

## Running

```bash
node server.js
```

Then open http://localhost:3000 in your browser.

## Project Structure
```
loan-planner/
├── server.js       # Lightweight HTTP server (no dependencies)
├── public/
│   └── index.html  # Full single-page application
└── README.md
```
