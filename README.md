# Student Evaluation Form Builder

Authors: Noah Whitworth (ncwhitwort42) and Seth Marter (slmarter42)

## Key Features

### Login and Registration

Users can register and log in using their Tennessee Tech email addresses.

- Register with a "@tntech.edu" email address to begin:
  - After matching log in credentials, users are redirected to the dashboard.
  - The dashboard contains options for creating, managing, and sharing evaluation forms.

### Custom Form Building

Users can build their own questions for the customization and convenience of both teachers and students. Teachers can decide to ask specific questions about the project, or instruct students to generate their own individual or group forms.

- Easily create evaluation forms with multiple question types:
  - Short Answer
  - Multiple Choice
  - Likert Scale
- Add, edit, and delete questions.
- Preview forms directly in the builder before saving.

### Form Management
- Generates unique 6-digit alphanumeric join codes for each form to enable easy sharing.
- Edit previously created forms.
- Delete unwanted forms with confirmation prompt.

### Alike User Permissions
- Users can join existing forms using the provided join codes.
- All users can view and fill out forms created by others.

This simplifies the evaluation process by allowing students to manage their own forms after grading is recorded.

## Version Disclaimers

The following features are not fully implemented and will be functional after a backend database is created:
- Email and Password is currently stored in an array for testing purposes. Login credentials will not persist after the page is refreshed. This will be updated in the future to use a backend database.
- New forms that you create are stored in localStorage until a backend is implemented. This means that your current forms WILL persist between sessions. To bypass the login page access dashboard.html directly.
- Since forms and their respective join codes are stored locally for now and without a respective object array, the Join Form button will not work until a backend is implemented.


