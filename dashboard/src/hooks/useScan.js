import { useState, useRef } from "react";
import { mockReport } from "../utils/mockData";

export const useScan = () => {
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState("");
  const [report, setReport] = useState(null);
  const [status, setStatus] = useState("idle");
  const intervalRef = useRef(null);

  const steps = [
    "Initializing scanner...",
    "Checking dependencies...",
    "Testing tools...",
    "Scanning for injections...",
    "Analyzing permissions...",
    "Generating report..."
  ];

  const triggerScan = () => {
    setStatus("scanning");
    setProgress(0);
    setReport(null);

    let currentProgress = 0;
    let stepIndex = 0;

    intervalRef.current = setInterval(() => {
      currentProgress += 18;
      stepIndex = Math.min(stepIndex + 1, steps.length - 1);
      setProgress(currentProgress);
      setCurrentStep(steps[stepIndex]);

      if (currentProgress >= 100) {
        clearInterval(intervalRef.current);
        setProgress(100);
        setCurrentStep("Done!");
        setTimeout(() => {
          setReport(mockReport);
          setStatus("done");
        }, 500);
      }
    }, 800);
  };

  return { triggerScan, progress, currentStep, report, status };
};